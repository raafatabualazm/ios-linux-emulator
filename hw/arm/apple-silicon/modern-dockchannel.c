/*
 * Declared, default-off DockChannel FIFO for /arm-io/dockchannel-mtp
 * (apple-modern machine option modern-mtp-input).
 *
 * Why it exists: with the stock hid-mtp compatible values restored,
 * AppleDockChannel::start reads window 0 + 0x4 of this block before anything
 * else.  The address was unmapped, the read was rejected, and the guest
 * re-executed the same load ~184,000 times in 15 s instead of booting
 * (evidence/features-20261014/claude-input run2: sampled PC unslid
 * 0xfffffff008aa2194 in com.apple.driver.AppleDockChannel, BootKC a36b9241,
 * register X9 -> GPA 0x314b00000).
 *
 * Declared register semantics.  Everything below is an explicit ANALOGY, not
 * measured Apple behaviour:
 *  - IRQ, config and data windows follow Asahi Linux's DockChannel FIFO driver
 *    (drivers/soc/apple/dockchannel.c, "apple,t8112-dockchannel"): IRQ_MASK
 *    0x0 / IRQ_FLAG 0x4; config TX_THRESH 0x0 / RX_THRESH 0x4; data TX8..TX32
 *    0x4..0x10, TX_FREE 0x14, RX8..RX32 0x1c..0x28, RX_COUNT 0x2c.  The T8140
 *    ADT window offsets (+0x14000 irq, +0x28000/+0x2c000 remote config/data,
 *    +0x30000/+0x34000 config/data) match that binding's layout.
 *  - Window 0 is not in Asahi's binding.  AppleDockChannel::start extracts
 *    bits [7:4] of +0x4 and requires ADT channel-number <= that field, logging
 *    "AppleDockChannel::start: Invalid channel-number" otherwise (same BootKC
 *    function).  The model reports channel-number + 1 there.
 *
 * No MTP firmware or remote peer exists.  Transmitted bytes are only counted
 * and logged; TX_FREE always reports the whole FIFO; the receive FIFO is empty
 * unless apple_modern_dockchannel_push_rx() fills it; IRQ_FLAG reports nothing
 * pending, so the interrupt never fires while the receive FIFO is empty.
 * Unknown offsets read as zero and ignore writes.  The first access to every
 * (window, offset, direction) is logged so the driver's real register usage can
 * be measured before any of this is promoted beyond "declared".
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/irq.h"
#include "hw/arm/apple-silicon/modern-dockchannel.h"

#define IRQ_MASK 0x0
#define IRQ_FLAG 0x4
#define CFG_TX_THRESH 0x0
#define CFG_RX_THRESH 0x4
#define DATA_TX8 0x4
#define DATA_TX16 0x8
#define DATA_TX24 0xc
#define DATA_TX32 0x10
#define DATA_TX_FREE 0x14
#define DATA_RX8 0x1c
#define DATA_RX16 0x20
#define DATA_RX24 0x24
#define DATA_RX32 0x28
#define DATA_RX_COUNT 0x2c
#define GLOBAL_CAPS 0x4
#define GLOBAL_CAPS_CHANNELS_SHIFT 4

/* Bound the per-write TX log; the running total is always kept. */
#define TX_LOG_WRITES 512

static const char *const window_names[APPLE_MODERN_DOCKCHANNEL_WINDOWS] = {
    "global", "irq", "config", "data", "rmt-config", "rmt-data",
};

/* Declared: receive-pending bit for this channel (unverified, see header). */
static uint32_t rx_flag(AppleModernDockChannelState *s)
{
    return BIT(2 * s->channel + 1);
}

static uint32_t pending(AppleModernDockChannelState *s)
{
    return s->rx_count ? rx_flag(s) : 0;
}

static void update_irq(AppleModernDockChannelState *s)
{
    qemu_set_irq(s->irq, (pending(s) & s->irq_mask) != 0);
}

static void log_first(AppleModernDockChannelState *s, unsigned win, hwaddr off,
                      bool write, uint64_t value, unsigned size)
{
    unsigned slot = off / 4;

    if (slot >= APPLE_MODERN_DOCKCHANNEL_WIN_SIZE / 4 ||
        test_and_set_bit(slot, s->seen[win][write])) {
        return;
    }
    warn_report("apple-modern: dockchannel-mtp first %s %s+0x%03" HWADDR_PRIx
                " size %u %s 0x%" PRIx64, write ? "write" : "read",
                window_names[win], off, size, write ? "<-" : "->", value);
}

static void tx_push(AppleModernDockChannelState *s, uint64_t value, unsigned n)
{
    char bytes[2 * 4 + 1] = "";

    s->tx_total += n;
    if (s->tx_logged >= TX_LOG_WRITES) {
        return;
    }
    s->tx_logged++;
    for (unsigned i = 0; i < n; i++) {
        snprintf(bytes + 2 * i, 3, "%02x", (unsigned)((value >> (8 * i)) & 0xff));
    }
    warn_report("apple-modern: dockchannel-mtp TX#%u %s (total %" PRIu64 " bytes)%s",
                s->tx_logged, bytes, s->tx_total,
                s->tx_logged == TX_LOG_WRITES ? "; further TX writes are counted only" : "");
}

static uint32_t rx_pop(AppleModernDockChannelState *s, unsigned n)
{
    uint32_t value = 0;

    for (unsigned i = 0; i < n && s->rx_count; i++) {
        value |= (uint32_t)s->rx[s->rx_head] << (8 * i);
        s->rx_head = (s->rx_head + 1) % APPLE_MODERN_DOCKCHANNEL_FIFO_MAX;
        s->rx_count--;
    }
    update_irq(s);
    return value;
}

static uint64_t dockchannel_read(void *opaque, hwaddr off, unsigned size)
{
    AppleModernDockChannelWindow *w = opaque;
    AppleModernDockChannelState *s = w->s;
    uint64_t value = 0;

    switch (w->index) {
    case APPLE_MODERN_DOCKCHANNEL_WIN_GLOBAL:
        if (off == GLOBAL_CAPS) {
            value = (uint64_t)(s->channel + 1) << GLOBAL_CAPS_CHANNELS_SHIFT;
        }
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_IRQ:
        value = off == IRQ_MASK ? s->irq_mask : off == IRQ_FLAG ? pending(s) : 0;
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_CONFIG:
        value = off == CFG_TX_THRESH ? s->tx_thresh :
                off == CFG_RX_THRESH ? s->rx_thresh : 0;
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_DATA:
        switch (off) {
        case DATA_TX_FREE:
            value = s->fifo_size;
            break;
        case DATA_RX8:
        case DATA_RX16:
        case DATA_RX24:
        case DATA_RX32:
            value = rx_pop(s, (off - DATA_RX8) / 4 + 1);
            break;
        case DATA_RX_COUNT:
            value = s->rx_count;
            break;
        }
        break;
    }
    log_first(s, w->index, off, false, value, size);
    return value;
}

static void dockchannel_write(void *opaque, hwaddr off, uint64_t value,
                              unsigned size)
{
    AppleModernDockChannelWindow *w = opaque;
    AppleModernDockChannelState *s = w->s;

    log_first(s, w->index, off, true, value, size);
    switch (w->index) {
    case APPLE_MODERN_DOCKCHANNEL_WIN_IRQ:
        if (off == IRQ_MASK) {
            s->irq_mask = value;
        }
        /* IRQ_FLAG: pending state is derived from the FIFO, nothing to clear. */
        update_irq(s);
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_CONFIG:
        if (off == CFG_TX_THRESH) {
            s->tx_thresh = value;
        } else if (off == CFG_RX_THRESH) {
            s->rx_thresh = value;
        }
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_DATA:
        if (off >= DATA_TX8 && off <= DATA_TX32 && !(off & 3)) {
            tx_push(s, value, (off - DATA_TX8) / 4 + 1);
        }
        break;
    }
}

static const MemoryRegionOps dockchannel_ops = {
    .read = dockchannel_read,
    .write = dockchannel_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    /* Accept every size: a rejected access is exactly the fault loop above. */
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
};

bool apple_modern_dockchannel_push_rx(AppleModernDockChannelState *s,
                                      const uint8_t *data, size_t len)
{
    if (len > s->fifo_size - s->rx_count) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        s->rx[(s->rx_head + s->rx_count) % APPLE_MODERN_DOCKCHANNEL_FIFO_MAX] = data[i];
        s->rx_count++;
    }
    update_irq(s);
    return true;
}

static void dockchannel_reset(DeviceState *dev)
{
    AppleModernDockChannelState *s = APPLE_MODERN_DOCKCHANNEL(dev);

    s->irq_mask = 0;
    s->tx_thresh = 0;
    s->rx_thresh = 0;
    s->rx_head = 0;
    s->rx_count = 0;
    update_irq(s);
}

SysBusDevice *apple_modern_dockchannel_new(uint32_t fifo_size, uint32_t channel)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_DOCKCHANNEL);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    AppleModernDockChannelState *s = APPLE_MODERN_DOCKCHANNEL(dev);

    assert(fifo_size && fifo_size <= APPLE_MODERN_DOCKCHANNEL_FIFO_MAX);
    assert(channel < 15);
    s->fifo_size = fifo_size;
    s->channel = channel;
    for (unsigned i = 0; i < APPLE_MODERN_DOCKCHANNEL_WINDOWS; i++) {
        g_autofree char *name = g_strdup_printf("dockchannel-mtp.%s", window_names[i]);

        s->win[i] = (AppleModernDockChannelWindow){ .s = s, .index = i };
        memory_region_init_io(&s->iomem[i], OBJECT(dev), &dockchannel_ops,
                              &s->win[i], name, APPLE_MODERN_DOCKCHANNEL_WIN_SIZE);
        sysbus_init_mmio(sbd, &s->iomem[i]);
    }
    sysbus_init_irq(sbd, &s->irq);
    return sbd;
}

static void dockchannel_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "Apple DockChannel FIFO (declared, modern-mtp-input)";
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, dockchannel_reset);
}

static const TypeInfo dockchannel_info = {
    .name = TYPE_APPLE_MODERN_DOCKCHANNEL,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernDockChannelState),
    .class_init = dockchannel_class_init,
};

static void dockchannel_register_types(void)
{
    type_register_static(&dockchannel_info);
}

type_init(dockchannel_register_types);
