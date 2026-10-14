/*
 * DockChannel FIFO for /arm-io/dockchannel-mtp (apple-modern machine option
 * modern-mtp-input, default off).
 *
 * Why it exists: with the stock hid-mtp compatible values restored,
 * AppleDockChannel::start reads window 0 + 0x4 of this block before anything
 * else.  The address was unmapped, the read was rejected, and the guest
 * re-executed the same load ~184,000 times in 15 s instead of booting
 * (evidence/features-20261014/claude-input run2: sampled PC unslid
 * 0xfffffff008aa2194 in com.apple.driver.AppleDockChannel, BootKC a36b9241,
 * register X9 -> GPA 0x314b00000).
 *
 * Register semantics are taken from the AP driver itself
 * (com.apple.driver.AppleDockChannel in BootKC a36b9241, unslid addresses;
 * annotated disassembly in evidence/features-20261014/claude-input/dis/):
 *  - start (0xfffffff008aa1d2c) maps ADT reg[0..5] as global, dock agent AP
 *    (interrupt), device config, device data, dock config and dock data.  It
 *    requires ADT channel-number <= bits [7:4] of global+0x4 ("Invalid
 *    channel-number"); the model reports channel-number + 1 there.
 *  - TX (0xfffffff008aa27f0): free = device-data+0x14 & dock-wstat-mask; whole
 *    words go to +0x10, a 1-3 byte tail to +0x4/+0x8/+0xc in the low bits.
 *  - RX (0xfffffff008aa2938, 0xfffffff008aa2bc0): available bytes =
 *    device-data+0x2c & 0xffff; each byte is device-data+0x1c >> 8.
 *  - Async read (0xfffffff008aa29fc): device-config+0x4 = requested length,
 *    agent+0x4 = 8 << (4 * channel) (clear), agent+0x0 |= the same bit
 *    (unmask); cancel (0xfffffff008aa2adc) masks, clears, zeroes +0x4 and may
 *    write 1 to device-config+0x10 / dock-config+0x10.
 * Inferred, not observed in that driver: the receive interrupt is level-like
 * (it latches again while device-data+0x2c >= device-config+0x4 after a
 * clear), bit 2 of the channel nibble is "transmit space", RX16/RX24 follow
 * RX8's byte-in-[31:8], count-in-[7:0] layout and RX32 returns four bytes,
 * +0x10 of either config window drops that side's queued bytes.  Asahi Linux
 * (drivers/soc/apple/dockchannel.c) uses the same layout on t8112.
 *
 * The far end is pluggable: apple_modern_dockchannel_set_peer() receives every
 * byte the AP transmits, apple_modern_dockchannel_push_rx() queues bytes for
 * the AP.  Without a peer, transmitted bytes are only counted and logged.  The
 * first access to every (window, offset, direction) is logged.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/irq.h"
#include "hw/arm/apple-silicon/modern-dockchannel.h"

#define AGENT_IRQ_MASK 0x0
#define AGENT_IRQ_FLAG 0x4
#define CFG_TX_THRESH 0x0
#define CFG_RX_THRESH 0x4
#define CFG_FLUSH 0x10
#define DATA_TX8 0x4
#define DATA_TX16 0x8
#define DATA_TX24 0xc
#define DATA_TX32 0x10
#define DATA_TX_FREE 0x14
#define DATA_RX_READY 0x18
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
    "global", "agent", "dev-config", "dev-data", "dock-config", "dock-data",
};

/* Per-channel interrupt nibble: bit 2 transmit space, bit 3 receive data. */
static uint32_t tx_bit(AppleModernDockChannelState *s)
{
    return 4u << (4 * s->channel);
}

static uint32_t rx_bit(AppleModernDockChannelState *s)
{
    return 8u << (4 * s->channel);
}

static uint32_t conditions(AppleModernDockChannelState *s)
{
    uint32_t bits = tx_bit(s);  /* the peer drains TX at once: always space */

    if (s->rx_count && s->rx_count >= s->rx_thresh) {
        bits |= rx_bit(s);
    }
    return bits;
}

/* Latch every condition that holds, then drive the line from flag & mask. */
static void update_irq(AppleModernDockChannelState *s)
{
    s->irq_flag |= conditions(s);
    qemu_set_irq(s->irq, (s->irq_flag & s->irq_mask) != 0);
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

static void tx_push(AppleModernDockChannelState *s, uint32_t value, unsigned n)
{
    uint8_t bytes[4];
    char hex[2 * 4 + 1] = "";

    for (unsigned i = 0; i < n; i++) {
        bytes[i] = value >> (8 * i);
        snprintf(hex + 2 * i, 3, "%02x", bytes[i]);
    }
    s->tx_total += n;
    if (s->tx_logged < TX_LOG_WRITES) {
        s->tx_logged++;
        warn_report("apple-modern: dockchannel-mtp TX#%u %s (total %" PRIu64
                    " bytes)%s", s->tx_logged, hex, s->tx_total,
                    s->tx_logged == TX_LOG_WRITES ?
                    "; further TX writes are counted only" : "");
    }
    if (s->peer_tx) {
        s->peer_tx(s->peer_opaque, bytes, n);
    }
}

static uint8_t rx_take(AppleModernDockChannelState *s)
{
    uint8_t byte = s->rx[s->rx_head];

    s->rx_head = (s->rx_head + 1) % APPLE_MODERN_DOCKCHANNEL_FIFO_MAX;
    s->rx_count--;
    return byte;
}

/* RX8/16/24: bytes in [31:8], count in [7:0].  RX32: four bytes. */
static uint32_t rx_read(AppleModernDockChannelState *s, unsigned n)
{
    uint32_t value = 0;
    unsigned got = 0;

    if (n == 4) {
        for (; got < 4 && s->rx_count; got++) {
            value |= (uint32_t)rx_take(s) << (8 * got);
        }
    } else {
        for (; got < n && s->rx_count; got++) {
            value |= (uint32_t)rx_take(s) << (8 * (got + 1));
        }
        value |= got;
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
    case APPLE_MODERN_DOCKCHANNEL_WIN_AGENT:
        value = off == AGENT_IRQ_MASK ? s->irq_mask :
                off == AGENT_IRQ_FLAG ? s->irq_flag : 0;
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_DEV_CONFIG:
        value = off == CFG_TX_THRESH ? s->tx_thresh :
                off == CFG_RX_THRESH ? s->rx_thresh : 0;
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_DEV_DATA:
        switch (off) {
        case DATA_TX_FREE:
            value = s->fifo_size;
            break;
        case DATA_RX_READY:
            value = MIN(s->rx_count, 0x7f);
            break;
        case DATA_RX8:
        case DATA_RX16:
        case DATA_RX24:
        case DATA_RX32:
            value = rx_read(s, (off - DATA_RX8) / 4 + 1);
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
    case APPLE_MODERN_DOCKCHANNEL_WIN_AGENT:
        if (off == AGENT_IRQ_MASK) {
            s->irq_mask = value;
        } else if (off == AGENT_IRQ_FLAG) {
            s->irq_flag &= ~(uint32_t)value;  /* write-1-to-clear */
        }
        update_irq(s);
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_DEV_CONFIG:
        if (off == CFG_TX_THRESH) {
            s->tx_thresh = value;
        } else if (off == CFG_RX_THRESH) {
            s->rx_thresh = value;
            update_irq(s);
        } else if (off == CFG_FLUSH && (value & 1) && s->rx_count) {
            warn_report("apple-modern: dockchannel-mtp device-side flush drops "
                        "%u queued RX bytes", s->rx_count);
            s->rx_head = 0;
            s->rx_count = 0;
            update_irq(s);
        }
        break;
    case APPLE_MODERN_DOCKCHANNEL_WIN_DEV_DATA:
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

uint32_t apple_modern_dockchannel_rx_space(AppleModernDockChannelState *s)
{
    return s->fifo_size - s->rx_count;
}

void apple_modern_dockchannel_set_peer(AppleModernDockChannelState *s,
                                       AppleModernDockChannelPeerTx tx,
                                       void *opaque)
{
    s->peer_tx = tx;
    s->peer_opaque = opaque;
}

static void dockchannel_reset(DeviceState *dev)
{
    AppleModernDockChannelState *s = APPLE_MODERN_DOCKCHANNEL(dev);

    s->irq_mask = 0;
    s->irq_flag = 0;
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
    assert(channel < 7);  /* irq nibble and caps field must fit */
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

    dc->desc = "Apple DockChannel FIFO (modern-mtp-input)";
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
