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
    /* Read only by the legacy TX-threshold path of apple_uart_update_irq(). */
    uint32_t last_irq;

    /*
     * Both opt-in, both default off, set only by -global; apple_uart_create()
     * never sets them. With both off every guest-visible behaviour is the
     * historical one (the one both boards ran before these properties
     * existed), including its two quirks:
     *
     *   drain-refresh  after a URXH read that empties the receive FIFO (or any
     *                  FIFO-disabled URXH read) re-evaluate the interrupt line.
     *                  Off: the line is left as it was until some other
     *                  register write refreshes it.
     *   ucon-store     store UCON writes, and with them let the TX-threshold,
     *                  RX-threshold and RX-timeout enables take effect, with the
     *                  containment described at each use (an edge-latched TX
     *                  request, write-1-to-clear UTRSTAT bits 2-5, a timeout
     *                  that needs data). Off: UCON writes are dropped and read
     *                  back 0.
     *
     * Every behaviour that differs from the historical one is behind one of the
     * two properties, not merely unreachable while UCON stays 0: a halfword
     * store to offset 6 lands in the generic register path and sets UCON without
     * ucon-store, so "unreachable" would not have been true.
     */
    bool ucon_store;
    bool drain_refresh;
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

/*
 * ucon-store only. The TX-threshold request is edge-latched, on the enable, not
 * level-derived from the FIFO count: the FIFO is never occupied here (UTXH is
 * written through synchronously), so a level-high request would be asserted
 * permanently and no acknowledge could end it.
 */
static bool apple_uart_tx_irq_enabled(const AppleUartState *s)
{
    return (s->reg[I_(UFCON)] & UFCON_FIFO_ENABLE) &&
           (s->reg[I_(UCON)] & UCON_TXTHRESH_ENA);
}

static bool apple_uart_tx_thresh_arm(AppleUartState *s, bool was_enabled)
{
    if (s->ucon_store && !was_enabled && apple_uart_tx_irq_enabled(s) &&
        fifo8_num_used(&s->tx) <= apple_uart_Tx_FIFO_trigger_level(s)) {
        s->reg[I_(UTRSTAT)] |= UTRSTAT_Tx_THRESH;
        return true;
    }
    return false;
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
            if (s->ucon_store) {
                /*
                 * Only the threshold request is an interrupt source here.
                 * Tx_EMPTY and Tx_BUFFER_EMPTY are status that is set whenever
                 * the transmitter is idle, which is always, and the acknowledge
                 * (UTRSTAT <- 0x20) cannot clear them: with them in the mask,
                 * enabling bit 13 raised the line at once and only clearing
                 * bit 13 lowered it again. The request itself is latched by
                 * apple_uart_tx_thresh_arm().
                 */
                mask |= UTRSTAT_Tx_THRESH;
            } else {
                /* Historical behaviour, unchanged. */
                mask |= UTRSTAT_Tx_THRESH | UTRSTAT_Tx_EMPTY |
                        UTRSTAT_Tx_BUFFER_EMPTY;
                if (count <= apple_uart_Tx_FIFO_trigger_level(s) &&
                    !(s->last_irq & UTRSTAT_Tx_THRESH)) {
                    s->reg[I_(UTRSTAT)] |= UTRSTAT_Tx_THRESH;
                }
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
        trace_apple_uart_irq_raised(s->channel, s->reg[I_(UTRSTAT)]);
    } else {
        qemu_irq_lower(s->irq);
        trace_apple_uart_irq_lowered(s->channel);
    }
}

static void apple_uart_timeout_int(void *opaque)
{
    AppleUartState *s = opaque;
    bool timed_out;

    trace_apple_uart_rx_timeout(s->channel, s->reg[I_(UTRSTAT)], 0);

    if (s->ucon_store) {
        /*
         * A timeout needs data to time out. The historical "or the enable bit
         * is set" clause latched it with an empty FIFO, which held the line
         * high until something cleared a status bit that nothing cleared
         * (measured on the ancestor build, where UCON is stored).
         */
        timed_out = (s->reg[I_(UCON)] & UCON_RXTIMEOUT_ENA) &&
                    (s->reg[I_(UTRSTAT)] & UTRSTAT_Rx_BUFFER_DATA_READY);
    } else {
        timed_out = (s->reg[I_(UTRSTAT)] & UTRSTAT_Rx_BUFFER_DATA_READY) ||
                    (s->reg[I_(UCON)] & UCON_RXTIMEOUT_ENA);
    }
    if (timed_out) {
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

    switch (offset) {
    case ULCON:
    case UBRDIV:
    case UFRACVAL:
        s->reg[I_(offset)] = val;
        apple_uart_update_parameters(s);
        break;
    case UFCON: {
        bool tx_was = apple_uart_tx_irq_enabled(s);

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
        /*
         * ucon-store: enabling the FIFO can arm the TX request. Refresh the
         * line only then, so without the property UFCON writes keep their
         * historical call pattern (the arm helper returns false at once).
         */
        if (apple_uart_tx_thresh_arm(s, tx_was)) {
            apple_uart_update_irq(s);
        }
        break;
    }

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
        if (s->ucon_store) {
            /*
             * Write 1 to clear the status bits 2-5. XNU acknowledges the TX
             * threshold by writing 0x20 (bit 5) and the Samsung driver writes
             * the pending bits back, which is primary evidence for bit 5 only;
             * bits 3 and 4 follow the same pattern as a declared choice, not a
             * measured fact.
             */
            val &= (UTRSTAT_Tx_EMPTY | UTRSTAT_Tx_THRESH | UTRSTAT_Rx_THRESH |
                    UTRSTAT_Rx_TIMEOUT);
        } else {
            val &= (UTRSTAT_Tx_EMPTY);
        }
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
    case UCON: {
        bool tx_was = apple_uart_tx_irq_enabled(s);

        /*
         * ucon-store: stored raw, with no reserved-bit mask, because the
         * guests' own value 0x405 has bit 10 set, which the model leaves
         * undefined. Without it the write is dropped, as it always was.
         */
        if (s->ucon_store) {
            s->reg[I_(UCON)] = (uint32_t)val;
            if (!(s->reg[I_(UCON)] & UCON_RXTIMEOUT_ENA)) {
                timer_del(s->fifo_timeout_timer);
            }
            apple_uart_tx_thresh_arm(s, tx_was);
        }
        apple_uart_update_irq(s);
        break;
    }
    case UMCON:
    default:
        s->reg[I_(offset)] = val;
        break;
    }
}

static uint64_t apple_uart_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleUartState *s = opaque;
    uint32_t res;
    bool level_changed = false;

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
                    if (s->ucon_store) {
                        /* Else a timeout latched with data pending outlives it. */
                        s->reg[I_(UTRSTAT)] &= ~UTRSTAT_Rx_TIMEOUT;
                    }
                    level_changed = true;
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
            level_changed = true;
        }
        qemu_chr_fe_accept_input(&s->chr);
        /*
         * drain-refresh: a drain is the one moment the level can fall, and
         * nothing else refreshed it. The owned-ROM gate measured the line
         * staying high after data-ready read 0, so re-unmasking it delivered a
         * second interrupt. Only a pop that empties the FIFO, or a
         * FIFO-disabled read, can lower the level. The refresh re-evaluates
         * the whole mask (a bare qemu_irq_lower() would drop a pending TX
         * request). The empty-FIFO error read is not refreshed: it changes no
         * status bit, and after a UFCON Rx reset with data pending data-ready is
         * still set, so a refresh there would leave the line high anyway. Its
         * position after qemu_chr_fe_accept_input() is a choice that no gate
         * pins (a backend that re-enters apple_uart_receive from there would
         * be covered by it, but the gates use a pipe backend, which cannot).
         */
        if (s->drain_refresh && level_changed) {
            apple_uart_update_irq(s);
        }
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
    DEFINE_PROP_BOOL("ucon-store", AppleUartState, ucon_store, false),
    DEFINE_PROP_BOOL("drain-refresh", AppleUartState, drain_refresh, false),
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
