/*
 * Apple Samsung S5L UART Emulation
 *
 * Copyright (c) 2025-2026 Visual Ehrmanntraut (VisualEhrmanntraut).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "chardev/char-fe.h"
#include "chardev/char-serial.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/fifo8.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "system/system.h"
#include "hw/core/cpu.h"
#include "qemu/bswap.h"

#include "hw/char/apple_uart.h"
#include "hw/irq.h"
#include "hw/qdev-properties-system.h"
#include "hw/qdev-properties.h"

#include "qom/object.h"
#include "trace.h"

/*
 *  Offsets for UART registers relative to SFR base address
 *  for UARTn
 *
 */
#define ULCON 0x0000 /* Line Control             */
#define UCON 0x0004 /* Control                  */
#define UFCON 0x0008 /* FIFO Control             */
#define UMCON 0x000C /* Modem Control            */
#define UTRSTAT 0x0010 /* Tx/Rx Status             */
#define UERSTAT 0x0014 /* UART Error Status        */
#define UFSTAT 0x0018 /* FIFO Status              */
#define UMSTAT 0x001C /* Modem Status             */
#define UTXH 0x0020 /* Transmit Buffer          */
#define URXH 0x0024 /* Receive Buffer           */
#define UBRDIV 0x0028 /* Baud Rate Divisor        */
#define UFRACVAL 0x002C /* Divisor Fractional Value */

/*
 * for indexing register in the uint32_t array
 *
 * 'reg' - register offset (see offsets definitions above)
 *
 */
#define I_(reg) (reg / sizeof(uint32_t))

typedef struct AppleUartReg {
    const char *name; /* the only reason is the debug output */
    hwaddr offset;
    uint32_t reset_value;
} AppleUartReg;

static const AppleUartReg apple_uart_regs[] = {
    { "ULCON", ULCON, 0x00000000 },
    { "UCON", UCON, 0x00000000 },
    { "UFCON", UFCON, 0x00000000 },
    { "UMCON", UMCON, 0x00000000 },
    { "UTRSTAT", UTRSTAT, 0x00000006 },
    { "UERSTAT", UERSTAT, 0x00000000 }, /* RO */
    { "UFSTAT", UFSTAT, 0x00000000 }, /* RO */
    { "UMSTAT", UMSTAT, 0x00000000 }, /* RO */
    { "UTXH", UTXH, 0x5c5c5c5c }, /* WO, undefined reset value*/
    { "URXH", URXH, 0x00000000 }, /* RO */
    { "UBRDIV", UBRDIV, 0x00000000 },
    { "UFRACVAL", UFRACVAL, 0x00000000 },
};

#define APPLE_UART_REGS_MEM_SIZE 0x3C

/* UART Control */
#define UCON_TXTHRESH_ENA (1 << 13)
#define UCON_RXTHRESH_ENA (1 << 12)
#define UCON_RXERR_ENA (1 << 11)
#define UCON_RXTIMEOUT_ENA (1 << 9)
#define UCON_TXMODE (3 << 2)
#define UCON_TXMODE_DMA (3 << 2)
#define UCON_TXMODE_IRQ (1 << 2)
#define UCON_RXMODE (3 << 0)
#define UCON_RXMODE_DMA (3 << 0)
#define UCON_RXMODE_IRQ (1 << 0)

/* UART FIFO Control */
#define UFCON_FIFO_ENABLE (1 << 0)
#define UFCON_Rx_FIFO_RESET (1 << 1)
#define UFCON_Tx_FIFO_RESET (1 << 2)
#define UFCON_Tx_FIFO_TRIGGER_LEVEL_SHIFT 6
#define UFCON_Tx_FIFO_TRIGGER_LEVEL (3 << UFCON_Tx_FIFO_TRIGGER_LEVEL_SHIFT)
#define UFCON_Rx_FIFO_TRIGGER_LEVEL_SHIFT 4
#define UFCON_Rx_FIFO_TRIGGER_LEVEL (3 << UFCON_Rx_FIFO_TRIGGER_LEVEL_SHIFT)

/* Uart FIFO Status */
#define UFSTAT_Rx_FIFO_COUNT 0xf
#define UFSTAT_Rx_FIFO_FULL (1 << 8)
#define UFSTAT_Tx_FIFO_COUNT_SHIFT 4
#define UFSTAT_Tx_FIFO_COUNT (0xf << UFSTAT_Tx_FIFO_COUNT_SHIFT)
#define UFSTAT_Tx_FIFO_FULL (1 << 9)

/* UART Line Control */
#define ULCON_IR_MODE_SHIFT 6
#define ULCON_PARITY_SHIFT 3
#define ULCON_STOP_BIT_SHIFT 1

/* UART Tx/Rx Status */
#define UTRSTAT_Rx_TIMEOUT (1 << 3)
#define UTRSTAT_Tx_THRESH (1 << 5)
#define UTRSTAT_Rx_THRESH (1 << 4)
#define UTRSTAT_Tx_EMPTY (1 << 2)
#define UTRSTAT_Tx_BUFFER_EMPTY (1 << 1)
#define UTRSTAT_Rx_BUFFER_DATA_READY (1 << 0)

/* UART Error Status */
#define UERSTAT_OVERRUN 0x1
#define UERSTAT_PARITY 0x2
#define UERSTAT_FRAME 0x4
#define UERSTAT_BREAK 0x8

typedef struct {
    uint8_t *data;
    uint32_t sp, rp; /* store and retrieve pointers */
    uint32_t size;
} AppleUartFIFO;

#define TYPE_APPLE_UART "apple-uart"
OBJECT_DECLARE_SIMPLE_TYPE(AppleUartState, APPLE_UART)


/* ---------------------------------------------------------------------------
 * PROBE (scratch instrumentation, observation only). Bounded counters plus
 * bounded log lines through qemu_log_mask(LOG_UNIMP, ...).
 * ------------------------------------------------------------------------- */
#define PROBE_NREG (APPLE_UART_REGS_MEM_SIZE / sizeof(uint32_t))
#define PROBE_DISTINCT 16

typedef struct ProbeVal {
    uint32_t val;
    uint64_t n;
} ProbeVal;

#define PROBE_SITES 64
typedef struct ProbeSite {
    uint8_t reg;
    bool wr;
    uint64_t pc, lr, n, v_or;
    uint32_t v_first;
} ProbeSite;

typedef struct AppleUartProbe {
    ProbeSite sites[PROBE_SITES];
    unsigned nsites;
    uint64_t sites_over;
    Notifier exit_notifier;
    uint64_t rd[PROBE_NREG], wr[PROBE_NREG];
    ProbeVal rv[PROBE_NREG][PROBE_DISTINCT];
    ProbeVal wv[PROBE_NREG][PROBE_DISTINCT];
    unsigned nrv[PROBE_NREG], nwv[PROBE_NREG];
    uint64_t rv_over[PROBE_NREG], wv_over[PROBE_NREG];

    /* UCON as the guest attempted to write it (the model drops it) */
    uint64_t ucon_writes, ucon_reads;
    uint32_t ucon_or, ucon_last;
    bool ucon_seen;
    uint64_t ucon_bit[32];
    uint64_t ucon_tx_ena, ucon_rx_ena, ucon_rxto_ena;

    /* interrupt line, as driven by apple_uart_update_irq() */
    bool line;
    uint64_t raise, lower, update_calls, update_calls_by_cause[8];
    uint64_t raise_by_cause[8], lower_by_cause[8];
    const char *cause;
    int cause_idx;

    /* receive path */
    uint64_t rx_calls, rx_bytes, rx_dropped, rx_nofifo, rx_while_line_high;
    uint64_t pops, empty_pops, nofifo_urxh, drains, drains_line_high;
    uint64_t timeouts, resets;

    /* stale line: FIFO drained by a URXH read while the line was left high */
    bool stale;
    uint64_t stale_t0_us, stale_acc;
    uint64_t stale_eps, stale_end_lower, stale_end_rx;
    uint64_t stale_us_total, stale_us_max, stale_acc_total, stale_acc_max;
    uint64_t stale_acc_rd[PROBE_NREG], stale_acc_wr[PROBE_NREG];
    uint64_t stale_end_by_cause[8];

    /* per-episode accounting: one episode = line high from RAISE to lower */
    uint64_t ep_t0, ep_drain_t, ep_base_data, ep_base_stale, ep_base_low;
    bool ep_open;
    uint64_t ep_n, ep_data_sum, ep_stale_sum, ep_total_max, ep_data_max;
    uint64_t ep_hist[8]; /* total acks in episode: 0,1,2,3-5,6-10,11-20,21-50,51+ */
    uint64_t ep_dur_max_us, ep_drain_lat_sum_us, ep_drain_lat_max_us;
    unsigned lb_ep;

    /* what-if switches, from the environment at realize time */
    bool sw_suppress_irq, sw_store_ucon, sw_refresh_drain;
    uint32_t sw_txfull_every, sw_txfull_burst;
    uint64_t sw_ufstat_reads, sw_txfull_injected, sw_suppressed_raises;

    /* log budgets */
    unsigned lb_ucon, lb_wdist, lb_rdist, lb_rx, lb_pop, lb_line, lb_stale;
    uint64_t last_tbpc;
} AppleUartProbe;

static const char *const probe_causes[] = {
    "rx", "UTXH", "UTRSTAT", "UCON", "UERSTAT", "timeout", "drain", "other"
};
#define PC_RX 0
#define PC_UTXH 1
#define PC_UTRSTAT 2
#define PC_UCON 3
#define PC_UERSTAT 4
#define PC_TIMEOUT 5
#define PC_EVENT 6 /* named "drain" */
#define PC_OTHER 7

/* Phase of the console line, read by the AIC probe: 0 low, 1 data waiting in
 * the RX FIFO, 2 FIFO drained but line still high (the "stale" window). */
int probe_uart_phase;
extern uint64_t probe_aic_ack_data, probe_aic_ack_stale, probe_aic_ack_low;

static uint64_t probe_now_us(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000;
}

static uint64_t probe_tbpc(void)
{
    if (current_cpu) {
        CPUClass *cc = CPU_GET_CLASS(current_cpu);

        if (cc->get_pc) {
            return cc->get_pc(current_cpu);
        }
    }
    return 0;
}

static uint64_t probe_lr(void)
{
    uint64_t lr = 0;

    if (current_cpu) {
        CPUClass *cc = CPU_GET_CLASS(current_cpu);

        if (cc->gdb_read_register) {
            GByteArray *ba = g_byte_array_new();

            if (cc->gdb_read_register(current_cpu, ba, 30) >= 8) {
                lr = ldq_le_p(ba->data);
            }
            g_byte_array_free(ba, true);
        }
    }
    return lr;
}

static void probe_site(AppleUartProbe *p, unsigned r, bool wr, uint64_t val)
{
    uint64_t pc = probe_tbpc(), lr = probe_lr();

    for (unsigned i = 0; i < p->nsites; i++) {
        ProbeSite *t = &p->sites[i];

        if (t->reg == r && t->wr == wr && t->pc == pc && t->lr == lr) {
            t->n++;
            t->v_or |= val;
            return;
        }
    }
    if (p->nsites < PROBE_SITES) {
        ProbeSite *t = &p->sites[p->nsites++];

        t->reg = r;
        t->wr = wr;
        t->pc = pc;
        t->lr = lr;
        t->n = 1;
        t->v_or = val;
        t->v_first = (uint32_t)val;
    } else {
        p->sites_over++;
    }
}

#define PLOG(s, budget, cap, fmt, ...) \
    do { \
        if ((s)->probe.budget < (cap)) { \
            (s)->probe.budget++; \
            qemu_log_mask(LOG_UNIMP, "uartprobe: t=%" PRIu64 "us " fmt "\n", \
                          probe_now_us(), ##__VA_ARGS__); \
        } \
    } while (0)

static void probe_note_val(ProbeVal *tab, unsigned *n, uint64_t *over,
                           uint32_t v, bool *fresh)
{
    *fresh = false;
    for (unsigned i = 0; i < *n; i++) {
        if (tab[i].val == v) {
            tab[i].n++;
            return;
        }
    }
    if (*n < PROBE_DISTINCT) {
        tab[*n].val = v;
        tab[*n].n = 1;
        (*n)++;
        *fresh = true;
    } else {
        (*over)++;
    }
}

struct AppleUartState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;

    uint32_t reg[APPLE_UART_REGS_MEM_SIZE / sizeof(uint32_t)];
    Fifo8 rx;
    Fifo8 tx;
    uint32_t rx_fifo_size;
    uint32_t tx_fifo_size;

    QEMUTimer *fifo_timeout_timer;
    uint64_t wordtime; /* word time in ns */

    CharBackend chr;
    qemu_irq irq;
    qemu_irq dmairq;

    uint32_t channel;
    uint32_t last_irq;
    AppleUartProbe probe;
};


/* Used only for tracing */
static const char *apple_uart_regname(hwaddr offset)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(apple_uart_regs); i++) {
        if (offset == apple_uart_regs[i].offset) {
            return apple_uart_regs[i].name;
        }
    }

    return NULL;
}


static uint32_t apple_uart_FIFO_trigger_level(uint32_t channel, uint32_t reg)
{
    uint32_t level;

    switch (channel) {
    case 0:
        level = reg * 32;
        break;
    case 1:
    case 4:
        level = reg * 8;
        break;
    case 2:
    case 3:
        level = reg * 2;
        break;
    default:
        level = 0;
        trace_apple_uart_channel_error(channel);
        break;
    }
    return level;
}

static uint32_t apple_uart_Tx_FIFO_trigger_level(const AppleUartState *s)
{
    uint32_t reg;

    reg = (s->reg[I_(UFCON)] & UFCON_Tx_FIFO_TRIGGER_LEVEL) >>
          UFCON_Tx_FIFO_TRIGGER_LEVEL_SHIFT;

    return apple_uart_FIFO_trigger_level(s->channel, reg);
}

static uint32_t apple_uart_Rx_FIFO_trigger_level(const AppleUartState *s)
{
    uint32_t reg;

    reg = ((s->reg[I_(UFCON)] & UFCON_Rx_FIFO_TRIGGER_LEVEL) >>
           UFCON_Rx_FIFO_TRIGGER_LEVEL_SHIFT) +
          1;

    return apple_uart_FIFO_trigger_level(s->channel, reg);
}


static void probe_stale_begin(AppleUartState *s, const char *how)
{
    AppleUartProbe *p = &s->probe;

    p->stale = true;
    p->stale_t0_us = probe_now_us();
    p->stale_acc = 0;
    p->stale_eps++;
    PLOG(s, lb_stale, 120, "STALE begin ep=%" PRIu64 " (%s) fifo_used=%u "
         "utrstat=0x%x line=%d", p->stale_eps, how, fifo8_num_used(&s->rx),
         s->reg[I_(UTRSTAT)], p->line);
}

static void probe_stale_end(AppleUartState *s, const char *how, int cause_idx)
{
    AppleUartProbe *p = &s->probe;
    uint64_t dur;

    if (!p->stale) {
        return;
    }
    p->stale = false;
    dur = probe_now_us() - p->stale_t0_us;
    p->stale_us_total += dur;
    if (dur > p->stale_us_max) {
        p->stale_us_max = dur;
    }
    p->stale_acc_total += p->stale_acc;
    if (p->stale_acc > p->stale_acc_max) {
        p->stale_acc_max = p->stale_acc;
    }
    p->stale_end_by_cause[cause_idx]++;
    PLOG(s, lb_stale, 120, "STALE end ep=%" PRIu64 " by=%s duration=%" PRIu64
         "us guest_uart_accesses_while_stale=%" PRIu64, p->stale_eps, how, dur,
         p->stale_acc);
}

static void probe_summary(AppleUartState *s, const char *tag)
{
    AppleUartProbe *p = &s->probe;
    static const char *const names[] = { "ULCON", "UCON", "UFCON", "UMCON",
        "UTRSTAT", "UERSTAT", "UFSTAT", "UMSTAT", "UTXH", "URXH", "UBRDIV",
        "UFRACVAL", "off0x30", "off0x34", "off0x38" };

    qemu_log_mask(LOG_UNIMP, "uartprobe: SUMMARY[%s] t=%" PRIu64 "us ch%u\n",
                  tag, probe_now_us(), s->channel);
    for (unsigned r = 0; r < PROBE_NREG; r++) {
        if (!p->rd[r] && !p->wr[r]) {
            continue;
        }
        qemu_log_mask(LOG_UNIMP, "uartprobe:   %-8s reads=%" PRIu64
                      " writes=%" PRIu64 "\n", names[r], p->rd[r], p->wr[r]);
        for (unsigned i = 0; i < p->nrv[r]; i++) {
            qemu_log_mask(LOG_UNIMP, "uartprobe:     read  0x%08x x%" PRIu64
                          "\n", p->rv[r][i].val, p->rv[r][i].n);
        }
        if (p->rv_over[r]) {
            qemu_log_mask(LOG_UNIMP, "uartprobe:     read  (other values) x%"
                          PRIu64 "\n", p->rv_over[r]);
        }
        for (unsigned i = 0; i < p->nwv[r]; i++) {
            qemu_log_mask(LOG_UNIMP, "uartprobe:     write 0x%08x x%" PRIu64
                          "\n", p->wv[r][i].val, p->wv[r][i].n);
        }
        if (p->wv_over[r]) {
            qemu_log_mask(LOG_UNIMP, "uartprobe:     write (other values) x%"
                          PRIu64 "\n", p->wv_over[r]);
        }
    }
    qemu_log_mask(LOG_UNIMP, "uartprobe:   UCON writes=%" PRIu64 " reads=%"
                  PRIu64 " or_of_values=0x%x last=0x%x tx_thresh_ena(bit13)=%"
                  PRIu64 " rx_thresh_ena(bit12)=%" PRIu64
                  " rx_timeout_ena(bit9)=%" PRIu64 " stored_now=0x%x\n",
                  p->ucon_writes, p->ucon_reads, p->ucon_or, p->ucon_last,
                  p->ucon_tx_ena, p->ucon_rx_ena, p->ucon_rxto_ena,
                  s->reg[I_(UCON)]);
    for (unsigned b = 0; b < 32; b++) {
        if (p->ucon_bit[b]) {
            qemu_log_mask(LOG_UNIMP, "uartprobe:   UCON bit%u set in %"
                          PRIu64 " of %" PRIu64 " writes\n", b,
                          p->ucon_bit[b], p->ucon_writes);
        }
    }
    qemu_log_mask(LOG_UNIMP, "uartprobe:   CONFIG suppress_irq=%d store_ucon=%d "
                  "refresh_on_drain=%d txfull_every=%u burst=%u injected=%"
                  PRIu64 " suppressed_raises=%" PRIu64 "\n",
                  p->sw_suppress_irq, p->sw_store_ucon, p->sw_refresh_drain,
                  p->sw_txfull_every, p->sw_txfull_burst,
                  p->sw_txfull_injected, p->sw_suppressed_raises);
    qemu_log_mask(LOG_UNIMP, "uartprobe:   line raise=%" PRIu64 " lower=%"
                  PRIu64 " update_irq_calls=%" PRIu64 " final_line=%d\n",
                  p->raise, p->lower, p->update_calls, p->line);
    for (unsigned c = 0; c < 8; c++) {
        if (p->update_calls_by_cause[c]) {
            qemu_log_mask(LOG_UNIMP, "uartprobe:   update_irq cause=%s calls="
                          "%" PRIu64 " raises=%" PRIu64 " lowers=%" PRIu64
                          "\n", probe_causes[c], p->update_calls_by_cause[c],
                          p->raise_by_cause[c], p->lower_by_cause[c]);
        }
    }
    qemu_log_mask(LOG_UNIMP, "uartprobe:   rx_calls=%" PRIu64 " rx_bytes=%"
                  PRIu64 " rx_dropped=%" PRIu64 " rx_with_fifo_disabled=%"
                  PRIu64 " rx_while_line_high=%" PRIu64 "\n", p->rx_calls,
                  p->rx_bytes, p->rx_dropped, p->rx_nofifo,
                  p->rx_while_line_high);
    qemu_log_mask(LOG_UNIMP, "uartprobe:   URXH pops=%" PRIu64
                  " empty_pops=%" PRIu64 " nofifo_urxh_reads=%" PRIu64
                  " drains(fifo emptied)=%" PRIu64
                  " drains_with_line_left_high=%" PRIu64 " timeouts=%" PRIu64
                  " resets=%" PRIu64 "\n", p->pops, p->empty_pops,
                  p->nofifo_urxh, p->drains, p->drains_line_high, p->timeouts,
                  p->resets);
    qemu_log_mask(LOG_UNIMP, "uartprobe:   STALE episodes=%" PRIu64
                  " ended_by_lower=%" PRIu64 " ended_by_new_rx=%" PRIu64
                  " still_open=%d total_us=%" PRIu64 " max_us=%" PRIu64
                  " guest_accesses_total=%" PRIu64 " max=%" PRIu64 "\n",
                  p->stale_eps, p->stale_end_lower, p->stale_end_rx, p->stale,
                  p->stale_us_total, p->stale_us_max, p->stale_acc_total,
                  p->stale_acc_max);
    qemu_log_mask(LOG_UNIMP, "uartprobe:   EPISODES(line-high intervals)=%"
                  PRIu64 " acks_while_data_waiting=%" PRIu64
                  " acks_while_drained_but_high=%" PRIu64 " max_total_acks_in_"
                  "one_episode=%" PRIu64 " max_data_acks_in_one_episode=%"
                  PRIu64 " longest_episode=%" PRIu64 "us drain_latency_sum="
                  "%" PRIu64 "us max=%" PRIu64 "us\n", p->ep_n,
                  p->ep_data_sum, p->ep_stale_sum, p->ep_total_max,
                  p->ep_data_max, p->ep_dur_max_us, p->ep_drain_lat_sum_us,
                  p->ep_drain_lat_max_us);
    qemu_log_mask(LOG_UNIMP, "uartprobe:   EPISODE histogram of total acks: "
                  "0:%" PRIu64 " 1:%" PRIu64 " 2:%" PRIu64 " 3-5:%" PRIu64
                  " 6-10:%" PRIu64 " 11-20:%" PRIu64 " 21-50:%" PRIu64
                  " 51+:%" PRIu64 "\n", p->ep_hist[0], p->ep_hist[1],
                  p->ep_hist[2], p->ep_hist[3], p->ep_hist[4], p->ep_hist[5],
                  p->ep_hist[6], p->ep_hist[7]);
    for (unsigned c = 0; c < 8; c++) {
        if (p->stale_end_by_cause[c]) {
            qemu_log_mask(LOG_UNIMP, "uartprobe:   STALE ended by %s x%"
                          PRIu64 "\n", probe_causes[c],
                          p->stale_end_by_cause[c]);
        }
    }
    for (unsigned r = 0; r < PROBE_NREG; r++) {
        if (p->stale_acc_rd[r] || p->stale_acc_wr[r]) {
            qemu_log_mask(LOG_UNIMP, "uartprobe:   during STALE %-8s reads=%"
                          PRIu64 " writes=%" PRIu64 "\n", names[r],
                          p->stale_acc_rd[r], p->stale_acc_wr[r]);
        }
    }
    for (unsigned i = 0; i < p->nsites; i++) {
        ProbeSite *t = &p->sites[i];

        qemu_log_mask(LOG_UNIMP, "uartprobe:   SITE %-8s %-5s pc=0x%" PRIx64
                      " lr=0x%" PRIx64 " x%" PRIu64 " first=0x%x or_of_values="
                      "0x%" PRIx64 "\n", names[t->reg], t->wr ? "write" :
                      "read", t->pc, t->lr, t->n, t->v_first, t->v_or);
    }
    if (p->sites_over) {
        qemu_log_mask(LOG_UNIMP, "uartprobe:   SITE (table full) x%" PRIu64
                      "\n", p->sites_over);
    }
    qemu_log_mask(LOG_UNIMP, "uartprobe: SUMMARY[%s] end\n", tag);
}

static void probe_exit_notify(Notifier *n, void *data)
{
    AppleUartProbe *p = container_of(n, AppleUartProbe, exit_notifier);
    AppleUartState *s = container_of(p, AppleUartState, probe);

    probe_summary(s, "exit");
}

/* Called for every guest register access before it is handled. */
static void probe_access(AppleUartState *s, hwaddr offset, uint64_t val,
                         bool is_write)
{
    AppleUartProbe *p = &s->probe;
    unsigned r = offset / 4;
    bool fresh;

    if (r >= PROBE_NREG) {
        return;
    }
    if (is_write) {
        probe_site(p, r, true, val);
    }
    if (p->stale) {
        p->stale_acc++;
        if (is_write) {
            p->stale_acc_wr[r]++;
        } else {
            p->stale_acc_rd[r]++;
        }
    }
    if (is_write) {
        p->wr[r]++;
        probe_note_val(p->wv[r], &p->nwv[r], &p->wv_over[r], (uint32_t)val,
                       &fresh);
        if (offset == UCON) {
            p->ucon_writes++;
            p->ucon_or |= (uint32_t)val;
            p->ucon_last = (uint32_t)val;
            for (unsigned b = 0; b < 32; b++) {
                if ((val >> b) & 1) {
                    p->ucon_bit[b]++;
                }
            }
            if (val & UCON_TXTHRESH_ENA) {
                p->ucon_tx_ena++;
            }
            if (val & UCON_RXTHRESH_ENA) {
                p->ucon_rx_ena++;
            }
            if (val & UCON_RXTIMEOUT_ENA) {
                p->ucon_rxto_ena++;
            }
            if (fresh || p->ucon_writes <= 8) {
                PLOG(s, lb_ucon, 80, "UCON write #%" PRIu64 " val=0x%" PRIx64
                     " (tx_thresh_ena=%d rx_thresh_ena=%d rx_timeout_ena=%d) "
                     "stored_before=0x%x tbpc=0x%" PRIx64, p->ucon_writes,
                     val, !!(val & UCON_TXTHRESH_ENA),
                     !!(val & UCON_RXTHRESH_ENA),
                     !!(val & UCON_RXTIMEOUT_ENA), s->reg[I_(UCON)],
                     probe_tbpc());
            }
        } else if (fresh) {
            PLOG(s, lb_wdist, 100, "write %s(0x%02" HWADDR_PRIx ") new value "
                 "0x%" PRIx64 " tbpc=0x%" PRIx64,
                 apple_uart_regname(offset) ? apple_uart_regname(offset) : "?",
                 offset, val, probe_tbpc());
        }
    } else {
        p->rd[r]++;
        if (offset == UCON) {
            p->ucon_reads++;
        }
    }
}

static void probe_read_result(AppleUartState *s, hwaddr offset, uint32_t res)
{
    AppleUartProbe *p = &s->probe;
    unsigned r = offset / 4;
    bool fresh;

    if (r >= PROBE_NREG) {
        return;
    }
    probe_site(p, r, false, res);
    probe_note_val(p->rv[r], &p->nrv[r], &p->rv_over[r], res, &fresh);
    if (fresh && offset != URXH) {
        PLOG(s, lb_rdist, 100, "read  %s(0x%02" HWADDR_PRIx ") new value "
             "0x%x tbpc=0x%" PRIx64,
             apple_uart_regname(offset) ? apple_uart_regname(offset) : "?",
             offset, res, probe_tbpc());
    }
}

static void apple_uart_update_irq(AppleUartState *s)
{
    /*
     * The Tx interrupt is always requested if the number of data in the
     * transmit FIFO is smaller than the trigger level.
     */
    uint32_t mask = UTRSTAT_Rx_BUFFER_DATA_READY;
    if (s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE) {
        uint32_t count = fifo8_num_used(&s->tx);

        if (s->reg[I_(UCON)] & UCON_TXTHRESH_ENA) {
            mask |=
                UTRSTAT_Tx_THRESH | UTRSTAT_Tx_EMPTY | UTRSTAT_Tx_BUFFER_EMPTY;
            if (count <= apple_uart_Tx_FIFO_trigger_level(s) &&
                !(s->last_irq & UTRSTAT_Tx_THRESH)) {
                s->reg[I_(UTRSTAT)] |= UTRSTAT_Tx_THRESH;
            }
        }

        /*
         * Rx interrupt if trigger level is reached or if rx timeout
         * interrupt is disabled and there is data in the receive buffer
         */
        count = fifo8_num_used(&s->rx);
        if (s->reg[I_(UCON)] & UCON_RXTHRESH_ENA) {
            mask |= UTRSTAT_Rx_THRESH;
            if (count >= apple_uart_Rx_FIFO_trigger_level(s)) {
                s->reg[I_(UTRSTAT)] |= UTRSTAT_Rx_THRESH;
                timer_del(s->fifo_timeout_timer);
            }
        }

        if (s->reg[I_(UCON)] & UCON_RXTIMEOUT_ENA) {
            mask |= UTRSTAT_Rx_TIMEOUT;
        }
    }

    {
        bool level = !!(s->reg[I_(UTRSTAT)] & mask);
        AppleUartProbe *p = &s->probe;
        int ci = p->cause_idx;

        p->update_calls++;
        p->update_calls_by_cause[ci]++;
        if (level != p->line) {
            if (level) {
                p->raise++;
                p->raise_by_cause[ci]++;
            } else {
                p->lower++;
                p->lower_by_cause[ci]++;
            }
            if (level) {
                p->ep_open = true;
                p->ep_t0 = probe_now_us();
                p->ep_drain_t = 0;
                p->ep_base_data = probe_aic_ack_data;
                p->ep_base_stale = probe_aic_ack_stale;
                p->ep_base_low = probe_aic_ack_low;
            } else if (p->ep_open) {
                uint64_t d = probe_aic_ack_data - p->ep_base_data;
                uint64_t st = probe_aic_ack_stale - p->ep_base_stale;
                uint64_t tot = d + st;
                uint64_t dur = probe_now_us() - p->ep_t0;
                uint64_t lat = p->ep_drain_t ? p->ep_drain_t - p->ep_t0 : 0;
                unsigned bin = tot == 0 ? 0 : tot == 1 ? 1 : tot == 2 ? 2 :
                               tot <= 5 ? 3 : tot <= 10 ? 4 : tot <= 20 ? 5 :
                               tot <= 50 ? 6 : 7;

                p->ep_open = false;
                p->ep_n++;
                p->ep_data_sum += d;
                p->ep_stale_sum += st;
                p->ep_hist[bin]++;
                if (tot > p->ep_total_max) {
                    p->ep_total_max = tot;
                }
                if (d > p->ep_data_max) {
                    p->ep_data_max = d;
                }
                if (dur > p->ep_dur_max_us) {
                    p->ep_dur_max_us = dur;
                }
                p->ep_drain_lat_sum_us += lat;
                if (lat > p->ep_drain_lat_max_us) {
                    p->ep_drain_lat_max_us = lat;
                }
                PLOG(s, lb_ep, 120, "EPISODE %" PRIu64 " line high %" PRIu64
                     "us; guest drained FIFO after %" PRIu64 "us; AIC acks "
                     "of irq 1092 while data waiting=%" PRIu64 " while drained"
                     "-but-high=%" PRIu64 " (total %" PRIu64 ")", p->ep_n, dur,
                     lat, d, st, tot);
            }
            PLOG(s, lb_line, 160, "LINE %s cause=%s utrstat=0x%x ucon_stored="
                 "0x%x ufcon=0x%x rx_fifo=%u stale=%d",
                 level ? "RAISE" : "lower", probe_causes[ci],
                 s->reg[I_(UTRSTAT)], s->reg[I_(UCON)], s->reg[I_(UFCON)],
                 fifo8_num_used(&s->rx), p->stale);
            if (!level && p->stale) {
                p->stale_end_lower++;
                probe_stale_end(s, probe_causes[ci], ci);
            }
            p->line = level;
        }
        probe_uart_phase = !level ? 0 : (fifo8_num_used(&s->rx) ? 1 : 2);
    }
    if (s->reg[I_(UTRSTAT)] & mask) {
        s->last_irq = s->reg[I_(UTRSTAT)] & mask;
        if (s->probe.sw_suppress_irq) {
            s->probe.sw_suppressed_raises++;
            qemu_irq_lower(s->irq);
        } else {
            qemu_irq_raise(s->irq);
        }
        trace_apple_uart_irq_raised(s->channel, s->reg[I_(UTRSTAT)]);
    } else {
        qemu_irq_lower(s->irq);
        trace_apple_uart_irq_lowered(s->channel);
    }
}

static void apple_uart_timeout_int(void *opaque)
{
    AppleUartState *s = opaque;

    trace_apple_uart_rx_timeout(s->channel, s->reg[I_(UTRSTAT)], 0);
    s->probe.timeouts++;
    s->probe.cause_idx = PC_TIMEOUT;

    if ((s->reg[I_(UTRSTAT)] & UTRSTAT_Rx_BUFFER_DATA_READY) ||
        (s->reg[I_(UCON)] & UCON_RXTIMEOUT_ENA)) {
        s->reg[I_(UTRSTAT)] |= UTRSTAT_Rx_TIMEOUT;
        apple_uart_update_irq(s);
    }
}

static void apple_uart_update_parameters(AppleUartState *s)
{
    int speed, parity, data_bits, stop_bits;
    QEMUSerialSetParams ssp;
    uint64_t uclk_rate;

    if (s->reg[I_(UBRDIV)] == 0) {
        return;
    }

    if (s->reg[I_(ULCON)] & 0x20) {
        if (s->reg[I_(ULCON)] & 0x28) {
            parity = 'E';
        } else {
            parity = 'O';
        }
    } else {
        parity = 'N';
    }

    if (s->reg[I_(ULCON)] & 0x4) {
        stop_bits = 2;
    } else {
        stop_bits = 1;
    }

    data_bits = (s->reg[I_(ULCON)] & 0x3) + 5;

    uclk_rate = 24000000;

    speed = uclk_rate / ((16 * (s->reg[I_(UBRDIV)]) & 0xffff) +
                         (s->reg[I_(UFRACVAL)] & 0x7) + 16);

    ssp.speed = speed;
    ssp.parity = parity;
    ssp.data_bits = data_bits;
    ssp.stop_bits = stop_bits;

    s->wordtime = NANOSECONDS_PER_SECOND * (data_bits + stop_bits + 1) / speed;

    qemu_chr_fe_ioctl(&s->chr, CHR_IOCTL_SERIAL_SET_PARAMS, &ssp);

    trace_apple_uart_update_params(s->channel, speed, parity, data_bits,
                                   stop_bits, s->wordtime);
}

static void apple_uart_rx_timeout_set(AppleUartState *s)
{
    if (s->reg[I_(UCON)] & UCON_RXTIMEOUT_ENA) {
        uint32_t timeout = ((s->reg[I_(UCON)] >> 12) & 0x0f) * s->wordtime;

        timer_mod(s->fifo_timeout_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + timeout);
    } else {
        timer_del(s->fifo_timeout_timer);
    }
}

static void apple_uart_write(void *opaque, hwaddr offset, uint64_t val,
                             unsigned size)
{
    AppleUartState *s = opaque;
    uint8_t ch;

    trace_apple_uart_write(s->channel, offset, apple_uart_regname(offset), val);
    probe_access(s, offset, val, true);
    s->probe.cause_idx = PC_OTHER;

    switch (offset) {
    case ULCON:
    case UBRDIV:
    case UFRACVAL:
        s->reg[I_(offset)] = val;
        apple_uart_update_parameters(s);
        break;
    case UFCON:
        s->reg[I_(UFCON)] = val;
        if (val & UFCON_Rx_FIFO_RESET) {
            fifo8_reset(&s->rx);
            s->reg[I_(UFCON)] &= ~UFCON_Rx_FIFO_RESET;
            trace_apple_uart_rx_fifo_reset(s->channel);
        }
        if (val & UFCON_Tx_FIFO_RESET) {
            fifo8_reset(&s->tx);
            s->reg[I_(UFCON)] &= ~UFCON_Tx_FIFO_RESET;
            trace_apple_uart_tx_fifo_reset(s->channel);
        }
        break;

    case UTXH:
        if (qemu_chr_fe_backend_connected(&s->chr)) {
            s->reg[I_(UTRSTAT)] &=
                ~(UTRSTAT_Tx_EMPTY | UTRSTAT_Tx_BUFFER_EMPTY);
            ch = (uint8_t)val;
            /* XXX this blocks entire thread. Rewrite to use
             * qemu_chr_fe_write and background I/O callbacks */
            qemu_chr_fe_write_all(&s->chr, &ch, 1);
            trace_apple_uart_tx(s->channel, ch);
            s->reg[I_(UTRSTAT)] |= UTRSTAT_Tx_EMPTY | UTRSTAT_Tx_BUFFER_EMPTY;
            s->probe.cause_idx = PC_UTXH;
            apple_uart_update_irq(s);
        }
        break;

    case UTRSTAT:
        val &= (UTRSTAT_Tx_EMPTY);
        s->reg[I_(UTRSTAT)] &= ~val;
        trace_apple_uart_intclr(s->channel, s->reg[I_(UTRSTAT)]);
        s->probe.cause_idx = PC_UTRSTAT;
        apple_uart_update_irq(s);
        break;
    case UERSTAT:
        s->reg[I_(UERSTAT)] &= ~val;
        s->probe.cause_idx = PC_UERSTAT;
        apple_uart_update_irq(s);
        break;
    case UFSTAT:
    case UMSTAT:
    case URXH:
        trace_apple_uart_ro_write(s->channel, apple_uart_regname(offset),
                                  offset);
        break;
    case UCON:
        if (s->probe.sw_store_ucon) {
            s->reg[I_(UCON)] = val;
        }
        s->probe.cause_idx = PC_UCON;
        apple_uart_update_irq(s);
        break;
    case UMCON:
    default:
        s->reg[I_(offset)] = val;
        break;
    }
}

static uint64_t apple_uart_read_inner(void *opaque, hwaddr offset,
                                      unsigned size)
{
    AppleUartState *s = opaque;
    uint32_t res;

    switch (offset) {
    case UERSTAT: /* Read Only */
        res = s->reg[I_(UERSTAT)];
        s->reg[I_(UERSTAT)] = 0;
        trace_apple_uart_read(s->channel, offset, apple_uart_regname(offset),
                              res);
        return res;
    case UFSTAT: /* Read Only */
        s->reg[I_(UFSTAT)] = fifo8_num_used(&s->rx) & 0xf;
        if (fifo8_num_free(&s->rx) == 0) {
            s->reg[I_(UFSTAT)] |= UFSTAT_Rx_FIFO_FULL;
        }
        trace_apple_uart_read(s->channel, offset, apple_uart_regname(offset),
                              s->reg[I_(UFSTAT)]);
        return s->reg[I_(UFSTAT)];
    case URXH:
        if (s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE) {
            if (fifo8_num_used(&s->rx)) {
                res = fifo8_pop(&s->rx);
                trace_apple_uart_rx(s->channel, res);
                if (fifo8_is_empty(&s->rx)) {
                    s->reg[I_(UTRSTAT)] &= ~UTRSTAT_Rx_BUFFER_DATA_READY;
                } else {
                    s->reg[I_(UTRSTAT)] |= UTRSTAT_Rx_BUFFER_DATA_READY;
                }
            } else {
                trace_apple_uart_rx_error(s->channel);
                res = 0;
            }
        } else {
            s->reg[I_(UTRSTAT)] &= ~UTRSTAT_Rx_BUFFER_DATA_READY;
            res = s->reg[I_(URXH)];
        }
        if (s->probe.sw_refresh_drain) {
            s->probe.cause_idx = PC_EVENT;
            apple_uart_update_irq(s);
        }
        qemu_chr_fe_accept_input(&s->chr);
        trace_apple_uart_read(s->channel, offset, apple_uart_regname(offset),
                              res);
        return res;
    case UTXH:
        trace_apple_uart_wo_read(s->channel, apple_uart_regname(offset),
                                 offset);
        break;
    default:
        trace_apple_uart_read(s->channel, offset, apple_uart_regname(offset),
                              s->reg[I_(offset)]);
        return s->reg[I_(offset)];
    }

    trace_apple_uart_read(s->channel, offset, apple_uart_regname(offset), 0);
    return 0;
}

static uint64_t apple_uart_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleUartState *s = opaque;
    AppleUartProbe *p = &s->probe;
    uint32_t used_before = fifo8_num_used(&s->rx);
    bool fifo_en = !!(s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE);
    uint64_t res;

    probe_access(s, offset, 0, false);
    res = apple_uart_read_inner(opaque, offset, size);
    if (offset == UFSTAT && p->sw_txfull_every) {
        uint64_t k = p->sw_ufstat_reads++ % p->sw_txfull_every;

        if (k < p->sw_txfull_burst) {
            res |= UFSTAT_Tx_FIFO_FULL;
            p->sw_txfull_injected++;
        }
    }
    probe_read_result(s, offset, (uint32_t)res);
    if (offset == URXH) {
        if (!fifo_en) {
            p->nofifo_urxh++;
        } else if (used_before == 0) {
            p->empty_pops++;
            PLOG(s, lb_pop, 120, "URXH read on EMPTY fifo (data=0x%x) line=%d "
                 "stale=%d", (unsigned)res, p->line, p->stale);
        } else {
            uint32_t used_after = fifo8_num_used(&s->rx);

            p->pops++;
            if (used_after == 0) {
                p->drains++;
                if (p->line) {
                    p->drains_line_high++;
                    PLOG(s, lb_pop, 120, "URXH pop 0x%02x -> FIFO now EMPTY, "
                         "utrstat=0x%x, LINE LEFT HIGH (no update_irq on this "
                         "path)", (unsigned)res, s->reg[I_(UTRSTAT)]);
                    probe_stale_begin(s, "URXH drain");
                    probe_uart_phase = 2;
                    if (p->ep_open && !p->ep_drain_t) {
                        p->ep_drain_t = probe_now_us();
                    }
                } else {
                    PLOG(s, lb_pop, 120, "URXH pop 0x%02x -> FIFO now EMPTY, "
                         "line already low", (unsigned)res);
                }
            } else {
                PLOG(s, lb_pop, 120, "URXH pop 0x%02x -> %u left, line=%d",
                     (unsigned)res, used_after, p->line);
            }
        }
    }
    return res;
}

static const MemoryRegionOps apple_uart_ops = {
    .read = apple_uart_read,
    .write = apple_uart_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .max_access_size = 4, .unaligned = false },
};

static int apple_uart_can_receive(void *opaque)
{
    AppleUartState *s = opaque;

    if (s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE) {
        return fifo8_num_free(&s->rx);
    } else {
        return !(s->reg[I_(UTRSTAT)] & UTRSTAT_Rx_BUFFER_DATA_READY);
    }
}

static void apple_uart_receive(void *opaque, const uint8_t *buf, int size)
{
    AppleUartState *s = opaque;
    AppleUartProbe *probe_p = &s->probe;
    bool probe_line_before = probe_p->line;
    int probe_size_in = size;

    probe_p->rx_calls++;
    if (probe_line_before) {
        probe_p->rx_while_line_high++;
    }
    if (probe_p->stale) {
        probe_p->stale_end_rx++;
        probe_stale_end(s, "new rx data", PC_RX);
    }

    if (s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE) {
        if (fifo8_num_free(&s->rx) < size) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: tx overflow: %d < %d\n",
                          __func__, fifo8_num_free(&s->rx), size);
            size = fifo8_num_free(&s->rx);
        }
        fifo8_push_all(&s->rx, buf, size);
        apple_uart_rx_timeout_set(s);
    } else {
        s->reg[I_(URXH)] = buf[0];
        probe_p->rx_nofifo++;
    }
    s->reg[I_(UTRSTAT)] |= UTRSTAT_Rx_BUFFER_DATA_READY;

    probe_p->rx_bytes += size;
    probe_p->rx_dropped += probe_size_in - size;
    s->probe.cause_idx = PC_RX;
    apple_uart_update_irq(s);
    PLOG(s, lb_rx, 120, "RX n=%d first=0x%02x fifo_used=%u fifo_en=%d "
         "line_before=%d line_after=%d", size, buf[0], fifo8_num_used(&s->rx),
         !!(s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE), probe_line_before,
         probe_p->line);
    if (!(probe_p->rx_calls & (probe_p->rx_calls - 1))) {
        qemu_log_mask(LOG_UNIMP, "uartprobe: rx_calls=%" PRIu64 " rx_bytes=%"
                      PRIu64 " raise=%" PRIu64 " lower=%" PRIu64
                      " pops=%" PRIu64 " drains=%" PRIu64
                      " drains_line_high=%" PRIu64 " ucon_writes=%" PRIu64
                      "\n", probe_p->rx_calls, probe_p->rx_bytes,
                      probe_p->raise, probe_p->lower, probe_p->pops,
                      probe_p->drains, probe_p->drains_line_high,
                      probe_p->ucon_writes);
    }
}


static void apple_uart_event(void *opaque, QEMUChrEvent event)
{
    AppleUartState *s = opaque;

    if (event == CHR_EVENT_BREAK) {
        /* When the RxDn is held in logic 0, then a null byte is pushed into the
         * fifo */
        fifo8_push(&s->rx, '\0');
        s->reg[I_(UERSTAT)] |= UERSTAT_BREAK;
        s->probe.cause_idx = PC_OTHER;
        apple_uart_update_irq(s);
    }
}


static void apple_uart_reset(DeviceState *dev)
{
    AppleUartState *s = APPLE_UART(dev);
    int i;

    for (i = 0; i < ARRAY_SIZE(apple_uart_regs); i++) {
        s->reg[I_(apple_uart_regs[i].offset)] = apple_uart_regs[i].reset_value;
    }

    fifo8_reset(&s->rx);
    fifo8_reset(&s->tx);
    s->probe.resets++;
    s->probe.line = false;
    s->probe.stale = false;
    qemu_log_mask(LOG_UNIMP, "uartprobe: device reset #%" PRIu64 "\n",
                  s->probe.resets);

    trace_apple_uart_rxsize(s->channel, s->rx_fifo_size);
}

static int apple_uart_post_load(void *opaque, int version_id)
{
    AppleUartState *s = opaque;

    apple_uart_update_parameters(s);
    apple_uart_rx_timeout_set(s);

    return 0;
}

static const VMStateDescription vmstate_apple_uart = {
    .name = "AppleUartState",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = apple_uart_post_load,
    .fields =
        (const VMStateField[]){
            VMSTATE_FIFO8(rx, AppleUartState),
            VMSTATE_UINT32_ARRAY(reg, AppleUartState,
                                 APPLE_UART_REGS_MEM_SIZE / sizeof(uint32_t)),
            VMSTATE_END_OF_LIST(),
        }
};

DeviceState *apple_uart_create(hwaddr addr, int fifo_size, int channel,
                               Chardev *chr, qemu_irq irq)
{
    DeviceState *dev;
    SysBusDevice *bus;

    dev = qdev_new(TYPE_APPLE_UART);

    qdev_prop_set_chr(dev, "chardev", chr);
    qdev_prop_set_uint32(dev, "channel", channel);
    qdev_prop_set_uint32(dev, "rx-size", fifo_size);
    qdev_prop_set_uint32(dev, "tx-size", fifo_size);

    bus = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(bus, &error_fatal);
    if (addr != (hwaddr)-1) {
        sysbus_mmio_map(bus, 0, addr);
    }
    sysbus_connect_irq(bus, 0, irq);

    return dev;
}

static void apple_uart_init(Object *obj)
{
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);
    AppleUartState *s = APPLE_UART(dev);

    s->wordtime = NANOSECONDS_PER_SECOND * 10 / 115200;

    /* memory mapping */
    memory_region_init_io(&s->iomem, obj, &apple_uart_ops, s, TYPE_APPLE_UART,
                          APPLE_UART_REGS_MEM_SIZE);
    sysbus_init_mmio(dev, &s->iomem);

    sysbus_init_irq(dev, &s->irq);
    sysbus_init_irq(dev, &s->dmairq);
}

static void apple_uart_realize(DeviceState *dev, Error **errp)
{
    AppleUartState *s = APPLE_UART(dev);

    if (s->rx_fifo_size >= 16) {
        error_setg(errp, "rx-size must be smaller than 16");
        return;
    }

    if (s->tx_fifo_size >= 16) {
        error_setg(errp, "tx-size must be smaller than 16");
        return;
    }

    fifo8_create(&s->rx, s->rx_fifo_size);
    fifo8_create(&s->tx, s->tx_fifo_size);
    s->probe.sw_suppress_irq = !!getenv("UARTPROBE_SUPPRESS_IRQ");
    s->probe.sw_store_ucon = !!getenv("UARTPROBE_STORE_UCON");
    s->probe.sw_refresh_drain = !!getenv("UARTPROBE_REFRESH_DRAIN");
    if (getenv("UARTPROBE_TXFULL_EVERY")) {
        s->probe.sw_txfull_every = atoi(getenv("UARTPROBE_TXFULL_EVERY"));
        s->probe.sw_txfull_burst = getenv("UARTPROBE_TXFULL_BURST") ?
            atoi(getenv("UARTPROBE_TXFULL_BURST")) : 1;
    }
    qemu_log_mask(LOG_UNIMP, "uartprobe: CONFIG suppress_irq=%d store_ucon=%d "
                  "refresh_on_drain=%d txfull_every=%u txfull_burst=%u\n",
                  s->probe.sw_suppress_irq, s->probe.sw_store_ucon,
                  s->probe.sw_refresh_drain, s->probe.sw_txfull_every,
                  s->probe.sw_txfull_burst);
    s->probe.exit_notifier.notify = probe_exit_notify;
    qemu_add_exit_notifier(&s->probe.exit_notifier);

    s->fifo_timeout_timer =
        timer_new_ns(QEMU_CLOCK_VIRTUAL, apple_uart_timeout_int, s);

    qemu_chr_fe_set_handlers(&s->chr, apple_uart_can_receive,
                             apple_uart_receive, apple_uart_event, NULL, s,
                             NULL, true);
}

static const Property apple_uart_properties[] = {
    DEFINE_PROP_CHR("chardev", AppleUartState, chr),
    DEFINE_PROP_UINT32("channel", AppleUartState, channel, 0),
    DEFINE_PROP_UINT32("rx-size", AppleUartState, rx_fifo_size, 15),
    DEFINE_PROP_UINT32("tx-size", AppleUartState, tx_fifo_size, 15),
};

static void apple_uart_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_uart_realize;
    device_class_set_legacy_reset(dc, apple_uart_reset);
    device_class_set_props(dc, apple_uart_properties);
    dc->vmsd = &vmstate_apple_uart;
}

static const TypeInfo apple_uart_info = {
    .name = TYPE_APPLE_UART,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleUartState),
    .instance_init = apple_uart_init,
    .class_init = apple_uart_class_init,
};

static void apple_uart_register(void)
{
    type_register_static(&apple_uart_info);
}

type_init(apple_uart_register)
