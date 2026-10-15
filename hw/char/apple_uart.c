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
    int probe_idx; /* TEMP PROBE */
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


/* ===================== TEMPORARY MEASUREMENT PROBE =====================
 * uart-probe worktree only. Never commit. All output goes to stderr with the
 * prefix "UARTPROBE". Behaviour of the model is NOT changed: the real
 * functions are only wrapped, and the probe keeps its own "shadow" copy of the
 * last value the guest wrote to UCON (the model itself drops that write).
 */
#define PROBE_MAX_CH 16
#define PROBE_HIST_N 24
#define PROBE_GLOBAL_LOG 300      /* first N accesses, all channels */
#define PROBE_CH_LOG 40           /* first N accesses of each channel */
#define PROBE_INTERESTING_LOG 300 /* later non-polling accesses (not UTXH/UTRSTAT/UFSTAT reads) */
#define PROBE_EVERY 5000
#define PROBE_TICK_NS (5ULL * 1000000000ULL)

typedef struct {
    uint32_t val[PROBE_HIST_N];
    uint64_t n[PROBE_HIST_N];
    uint64_t overflow;
} ProbeHist;

typedef struct {
    bool used;
    AppleUartState *s;
    uint64_t base;
    uint64_t acc, last_tick_acc, summaries;
    uint64_t rd[12], wr[12]; /* per register (offset / 4) */
    ProbeHist ucon_hist, ufcon_hist, utrstat_w_hist;
    uint64_t ucon_txthr, ucon_rxthr, ucon_rxto, ucon_rxerr, ucon_any3;
    uint64_t ucon_modes_irq;
    uint64_t urxh_data, urxh_empty, urxh_left_line_high;
    uint64_t utxh_conn, utxh_noconn;
    uint64_t rx_calls, rx_bytes, can_rx_calls, ioctl_like;
    uint64_t irq_calls, raise_calls, raise_edges, lower_calls, lower_edges;
    bool level;
    uint32_t shadow_ucon;
    uint64_t shadow_fifo_off, shadow_tx_would, shadow_rx_would, shadow_rxto_en;
    uint64_t first_acc_ns, first_ucon_ns, first_any3_ns, first_rxbyte_ns, first_urxh_ns;
} ProbeChan;

static ProbeChan probe_ch[PROBE_MAX_CH];
static int probe_nch;
static uint64_t probe_global_acc, probe_interesting_logged, probe_summary_lines;
static QEMUTimer *probe_timer;
static int probe_inject_done;
static const char *probe_regnames[12] = { "ULCON", "UCON", "UFCON", "UMCON",
    "UTRSTAT", "UERSTAT", "UFSTAT", "UMSTAT", "UTXH", "URXH", "UBRDIV", "UFRACVAL" };

static uint64_t probe_now(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static void probe_hist_add(ProbeHist *h, uint32_t v)
{
    for (int i = 0; i < PROBE_HIST_N; i++) {
        if (h->n[i] && h->val[i] == v) {
            h->n[i]++;
            return;
        }
        if (!h->n[i]) {
            h->val[i] = v;
            h->n[i] = 1;
            return;
        }
    }
    h->overflow++;
}

static void probe_hist_print(const char *name, int idx, const ProbeHist *h)
{
    fprintf(stderr, "UARTPROBE   ch%d %s:", idx, name);
    for (int i = 0; i < PROBE_HIST_N && h->n[i]; i++) {
        fprintf(stderr, " 0x%x*%" PRIu64, h->val[i], h->n[i]);
    }
    if (h->overflow) {
        fprintf(stderr, " (+%" PRIu64 " other)", h->overflow);
    }
    fprintf(stderr, "\n");
}

static ProbeChan *probe_chan(AppleUartState *s)
{
    return &probe_ch[s->probe_idx];
}

static void probe_summary(ProbeChan *p, const char *why)
{
    int idx = (int)(p - probe_ch);
    fprintf(stderr,
            "UARTPROBE SUM[%s] ch%d id=%s base=0x%" PRIx64 " t=%" PRIu64 "ms acc=%" PRIu64
            " UCONw=%" PRIu64 " txthr=%" PRIu64 " rxthr=%" PRIu64 " rxto=%" PRIu64
            " rxerr=%" PRIu64 " any_of_3=%" PRIu64 " modes_irq=%" PRIu64
            " URXHr=%" PRIu64 " (data=%" PRIu64 " empty=%" PRIu64 " left_line_high=%" PRIu64 ")"
            " UTXHw=%" PRIu64 " (nobackend=%" PRIu64 ") UTRSTATw=%" PRIu64
            " rx_calls=%" PRIu64 " rx_bytes=%" PRIu64 " can_rx=%" PRIu64
            " irq_calls=%" PRIu64 " raise=%" PRIu64 "(edges %" PRIu64 ") lower=%" PRIu64
            "(edges %" PRIu64 ") level=%d shadow_ucon=0x%x shadow(fifo_off=%" PRIu64
            " tx_would=%" PRIu64 " rx_would=%" PRIu64 " rxto_en=%" PRIu64 ")\n",
            why, idx, DEVICE(p->s)->id ? DEVICE(p->s)->id : "?", p->base,
            probe_now() / 1000000, p->acc, p->wr[I_(UCON)], p->ucon_txthr, p->ucon_rxthr,
            p->ucon_rxto, p->ucon_rxerr, p->ucon_any3, p->ucon_modes_irq, p->rd[I_(URXH)],
            p->urxh_data, p->urxh_empty, p->urxh_left_line_high, p->wr[I_(UTXH)],
            p->utxh_noconn, p->wr[I_(UTRSTAT)], p->rx_calls, p->rx_bytes, p->can_rx_calls,
            p->irq_calls, p->raise_calls, p->raise_edges, p->lower_calls, p->lower_edges,
            p->level, p->shadow_ucon, p->shadow_fifo_off, p->shadow_tx_would,
            p->shadow_rx_would, p->shadow_rxto_en);
    fprintf(stderr, "UARTPROBE   ch%d first_ns: acc=%" PRIu64 " UCONw=%" PRIu64 " any_of_3=%" PRIu64
            " rxbyte=%" PRIu64 " URXHread=%" PRIu64 "\n", idx, p->first_acc_ns,
            p->first_ucon_ns, p->first_any3_ns, p->first_rxbyte_ns, p->first_urxh_ns);
    fprintf(stderr, "UARTPROBE   ch%d per-reg reads/writes:", idx);
    for (int i = 0; i < 12; i++) {
        fprintf(stderr, " %s=%" PRIu64 "/%" PRIu64, probe_regnames[i], p->rd[i], p->wr[i]);
    }
    fprintf(stderr, "\n");
    probe_hist_print("UCON writes", idx, &p->ucon_hist);
    probe_hist_print("UFCON writes", idx, &p->ufcon_hist);
    probe_hist_print("UTRSTAT writes", idx, &p->utrstat_w_hist);
}

static void probe_final(void)
{
    for (int i = 0; i < probe_nch; i++) {
        if (probe_ch[i].used && probe_ch[i].acc) {
            probe_summary(&probe_ch[i], "final");
        }
    }
}

static void probe_log_access(ProbeChan *p, bool is_write, hwaddr off, uint64_t val,
                             unsigned size)
{
    bool polling = (!is_write && (off == UTRSTAT || off == UFSTAT)) ||
                   (is_write && off == UTXH);
    bool log = false;

    probe_global_acc++;
    p->acc++;
    p->base = p->s->iomem.addr;
    if (!p->first_acc_ns) {
        p->first_acc_ns = probe_now();
    }
    if (probe_global_acc <= PROBE_GLOBAL_LOG || p->acc <= PROBE_CH_LOG) {
        log = true;
    } else if (!polling && probe_interesting_logged < PROBE_INTERESTING_LOG) {
        probe_interesting_logged++;
        log = true;
    }
    if (log) {
        fprintf(stderr, "UARTPROBE acc g%" PRIu64 " ch%d %c %s(0x%02" PRIx64 ") val=0x%" PRIx64
                " size=%u t=%" PRIu64 "us\n", probe_global_acc, (int)(p - probe_ch),
                is_write ? 'W' : 'R',
                off / 4 < 12 ? probe_regnames[off / 4] : "?", (uint64_t)off, val, size,
                probe_now() / 1000);
    }
}

static void probe_after_access(ProbeChan *p)
{
    if (p->acc % PROBE_EVERY == 0 &&
        (p->summaries < 20 || p->acc % (20 * PROBE_EVERY) == 0) &&
        probe_summary_lines < 400) {
        p->summaries++;
        probe_summary_lines++;
        probe_summary(p, "periodic");
    }
}

static void probe_note_write(AppleUartState *s, hwaddr off, uint64_t val, unsigned size)
{
    ProbeChan *p = probe_chan(s);

    if (off / 4 < 12) {
        p->wr[off / 4]++;
    }
    probe_log_access(p, true, off, val, size);
    switch (off) {
    case UCON: {
        uint32_t v = (uint32_t)val;
        bool a = v & UCON_TXTHRESH_ENA, b = v & UCON_RXTHRESH_ENA, c = v & UCON_RXTIMEOUT_ENA;
        probe_hist_add(&p->ucon_hist, v);
        p->shadow_ucon = v;
        p->ucon_txthr += a;
        p->ucon_rxthr += b;
        p->ucon_rxto += c;
        p->ucon_rxerr += !!(v & UCON_RXERR_ENA);
        p->ucon_any3 += (a || b || c);
        p->ucon_modes_irq += (((v & UCON_TXMODE) == UCON_TXMODE_IRQ) ||
                              ((v & UCON_RXMODE) == UCON_RXMODE_IRQ));
        if (!p->first_ucon_ns) {
            p->first_ucon_ns = probe_now();
        }
        if ((a || b || c) && !p->first_any3_ns) {
            p->first_any3_ns = probe_now();
            fprintf(stderr, "UARTPROBE !!! ch%d FIRST UCON write with a threshold/timeout "
                    "enable: 0x%x at t=%" PRIu64 "us\n", (int)(p - probe_ch), v,
                    probe_now() / 1000);
        }
        break;
    }
    case UFCON:
        probe_hist_add(&p->ufcon_hist, (uint32_t)val);
        break;
    case UTRSTAT:
        probe_hist_add(&p->utrstat_w_hist, (uint32_t)val);
        break;
    case UTXH:
        if (qemu_chr_fe_backend_connected(&s->chr)) {
            p->utxh_conn++;
        } else {
            p->utxh_noconn++;
        }
        break;
    default:
        break;
    }
}

static void probe_note_read_pre(AppleUartState *s, hwaddr off, bool *had_data)
{
    *had_data = (off == URXH) && fifo8_num_used(&s->rx) > 0;
}

static void probe_note_read_post(AppleUartState *s, hwaddr off, uint64_t val, unsigned size,
                                 bool had_data)
{
    ProbeChan *p = probe_chan(s);

    if (off / 4 < 12) {
        p->rd[off / 4]++;
    }
    probe_log_access(p, false, off, val, size);
    if (off == URXH) {
        if (!p->first_urxh_ns) {
            p->first_urxh_ns = probe_now();
        }
        if (had_data) {
            p->urxh_data++;
            if (fifo8_is_empty(&s->rx) && p->level) {
                p->urxh_left_line_high++; /* defect 2: drained but line still asserted */
            }
        } else {
            p->urxh_empty++;
        }
    }
}

static void probe_irq_call(AppleUartState *s)
{
    ProbeChan *p = probe_chan(s);

    p->irq_calls++;
    if (!(s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE)) {
        p->shadow_fifo_off++;
        return;
    }
    if ((p->shadow_ucon & UCON_TXTHRESH_ENA) &&
        fifo8_num_used(&s->tx) <= apple_uart_Tx_FIFO_trigger_level(s)) {
        p->shadow_tx_would++;
    }
    if ((p->shadow_ucon & UCON_RXTHRESH_ENA) &&
        fifo8_num_used(&s->rx) >= apple_uart_Rx_FIFO_trigger_level(s)) {
        p->shadow_rx_would++;
    }
    if (p->shadow_ucon & UCON_RXTIMEOUT_ENA) {
        p->shadow_rxto_en++;
    }
}

static void probe_irq_level(AppleUartState *s, bool raise)
{
    ProbeChan *p = probe_chan(s);

    if (raise) {
        p->raise_calls++;
        p->raise_edges += !p->level;
        p->level = true;
    } else {
        p->lower_calls++;
        p->lower_edges += p->level;
        p->level = false;
    }
}

static void apple_uart_receive(void *opaque, const uint8_t *buf, int size);

static void probe_tick(void *opaque)
{
    uint64_t now = probe_now();
    const char *inj = getenv("UARTPROBE_INJECT_S");

    for (int i = 0; i < probe_nch; i++) {
        ProbeChan *p = &probe_ch[i];
        if (p->used && p->acc != p->last_tick_acc && probe_summary_lines < 400) {
            p->last_tick_acc = p->acc;
            probe_summary_lines++;
            probe_summary(p, "tick");
        }
    }
    /* Optional stimulus: UARTPROBE_INJECT_S=N feeds 3 bytes to uart0, 5 s apart, from
     * N seconds of virtual time on. Off unless the environment variable is set. */
    if (inj && probe_nch > 0 && probe_inject_done < 3 && now >= atoll(inj) * 1000000000ULL) {
        static const uint8_t b = 'x';
        probe_inject_done++;
        fprintf(stderr, "UARTPROBE >>> injecting byte %d into ch0 at t=%" PRIu64 "ms\n",
                probe_inject_done, now / 1000000);
        apple_uart_receive(probe_ch[0].s, &b, 1);
    }
    timer_mod(probe_timer, now + PROBE_TICK_NS);
}

static void probe_register(AppleUartState *s)
{
    static bool once;

    if (probe_nch >= PROBE_MAX_CH) {
        s->probe_idx = PROBE_MAX_CH - 1;
        return;
    }
    s->probe_idx = probe_nch++;
    probe_ch[s->probe_idx].used = true;
    probe_ch[s->probe_idx].s = s;
    if (!once) {
        once = true;
        atexit(probe_final);
        probe_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, probe_tick, NULL);
        timer_mod(probe_timer, probe_now() + PROBE_TICK_NS);
        fprintf(stderr, "UARTPROBE armed (temporary instrumentation)\n");
    }
}
/* =================== END TEMPORARY MEASUREMENT PROBE =================== */

static void apple_uart_update_irq(AppleUartState *s)
{
    /*
     * The Tx interrupt is always requested if the number of data in the
     * transmit FIFO is smaller than the trigger level.
     */
    uint32_t mask = UTRSTAT_Rx_BUFFER_DATA_READY;
    probe_irq_call(s); /* TEMP PROBE */
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

    if (s->reg[I_(UTRSTAT)] & mask) {
        s->last_irq = s->reg[I_(UTRSTAT)] & mask;
        qemu_irq_raise(s->irq);
        probe_irq_level(s, true); /* TEMP PROBE */
        trace_apple_uart_irq_raised(s->channel, s->reg[I_(UTRSTAT)]);
    } else {
        qemu_irq_lower(s->irq);
        probe_irq_level(s, false); /* TEMP PROBE */
        trace_apple_uart_irq_lowered(s->channel);
    }
}

static void apple_uart_timeout_int(void *opaque)
{
    AppleUartState *s = opaque;

    trace_apple_uart_rx_timeout(s->channel, s->reg[I_(UTRSTAT)], 0);

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

static void apple_uart_write_real(void *opaque, hwaddr offset, uint64_t val,
                                  unsigned size)
{
    AppleUartState *s = opaque;
    uint8_t ch;

    trace_apple_uart_write(s->channel, offset, apple_uart_regname(offset), val);

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
            apple_uart_update_irq(s);
        }
        break;

    case UTRSTAT:
        val &= (UTRSTAT_Tx_EMPTY);
        s->reg[I_(UTRSTAT)] &= ~val;
        trace_apple_uart_intclr(s->channel, s->reg[I_(UTRSTAT)]);
        apple_uart_update_irq(s);
        break;
    case UERSTAT:
        s->reg[I_(UERSTAT)] &= ~val;
        apple_uart_update_irq(s);
        break;
    case UFSTAT:
    case UMSTAT:
    case URXH:
        trace_apple_uart_ro_write(s->channel, apple_uart_regname(offset),
                                  offset);
        break;
    case UCON:
        apple_uart_update_irq(s);
        break;
    case UMCON:
    default:
        s->reg[I_(offset)] = val;
        break;
    }
}

static uint64_t apple_uart_read_real(void *opaque, hwaddr offset, unsigned size)
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


/* TEMP PROBE wrappers: observe, then call the unchanged model code. */
static void apple_uart_write(void *opaque, hwaddr offset, uint64_t val,
                             unsigned size)
{
    probe_note_write(opaque, offset, val, size);
    apple_uart_write_real(opaque, offset, val, size);
    probe_after_access(probe_chan(opaque));
}

static uint64_t apple_uart_read(void *opaque, hwaddr offset, unsigned size)
{
    bool had_data;
    uint64_t res;

    probe_note_read_pre(opaque, offset, &had_data);
    res = apple_uart_read_real(opaque, offset, size);
    probe_note_read_post(opaque, offset, res, size, had_data);
    probe_after_access(probe_chan(opaque));
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

    probe_chan(s)->can_rx_calls++; /* TEMP PROBE */

    if (s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE) {
        return fifo8_num_free(&s->rx);
    } else {
        return !(s->reg[I_(UTRSTAT)] & UTRSTAT_Rx_BUFFER_DATA_READY);
    }
}

static void apple_uart_receive(void *opaque, const uint8_t *buf, int size)
{
    AppleUartState *s = opaque;

    /* TEMP PROBE */
    probe_chan(s)->rx_calls++;
    probe_chan(s)->rx_bytes += size;
    if (!probe_chan(s)->first_rxbyte_ns) {
        probe_chan(s)->first_rxbyte_ns = probe_now();
    }
    fprintf(stderr, "UARTPROBE RX ch%d %d byte(s) first=0x%02x\n", s->probe_idx, size, buf[0]);

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
    }
    s->reg[I_(UTRSTAT)] |= UTRSTAT_Rx_BUFFER_DATA_READY;

    apple_uart_update_irq(s);
}


static void apple_uart_event(void *opaque, QEMUChrEvent event)
{
    AppleUartState *s = opaque;

    if (event == CHR_EVENT_BREAK) {
        /* When the RxDn is held in logic 0, then a null byte is pushed into the
         * fifo */
        fifo8_push(&s->rx, '\0');
        s->reg[I_(UERSTAT)] |= UERSTAT_BREAK;
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
    probe_register(s); /* TEMP PROBE */

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
