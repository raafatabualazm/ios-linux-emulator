/*
 * DockChannel FIFO for /arm-io/dockchannel-mtp (apple-modern machine option
 * modern-mtp-input, default off).  See modern-dockchannel.c for the register
 * semantics and the driver code they come from.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_ARM_APPLE_SILICON_MODERN_DOCKCHANNEL_H
#define HW_ARM_APPLE_SILICON_MODERN_DOCKCHANNEL_H

#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "qom/object.h"

#define TYPE_APPLE_MODERN_DOCKCHANNEL "apple-modern-dockchannel"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernDockChannelState, APPLE_MODERN_DOCKCHANNEL)

/*
 * ADT reg order of T8140 /arm-io/dockchannel-mtp (offsets from 0x314b00000),
 * named as AppleDockChannel::start names them.
 */
enum {
    APPLE_MODERN_DOCKCHANNEL_WIN_GLOBAL,      /* +0x00000 */
    APPLE_MODERN_DOCKCHANNEL_WIN_AGENT,       /* +0x14000 dock agent AP (IRQ) */
    APPLE_MODERN_DOCKCHANNEL_WIN_DEV_CONFIG,  /* +0x30000 */
    APPLE_MODERN_DOCKCHANNEL_WIN_DEV_DATA,    /* +0x34000 */
    APPLE_MODERN_DOCKCHANNEL_WIN_DOCK_CONFIG, /* +0x28000 */
    APPLE_MODERN_DOCKCHANNEL_WIN_DOCK_DATA,   /* +0x2c000 */
    APPLE_MODERN_DOCKCHANNEL_WINDOWS
};

/* Called with every byte run the AP transmits. */
typedef void (*AppleModernDockChannelPeerTx)(void *opaque, const uint8_t *data,
                                             size_t len);

#define APPLE_MODERN_DOCKCHANNEL_WIN_SIZE 0x1000
#define APPLE_MODERN_DOCKCHANNEL_FIFO_MAX 0x1000

typedef struct AppleModernDockChannelWindow {
    AppleModernDockChannelState *s;
    unsigned index;
} AppleModernDockChannelWindow;

struct AppleModernDockChannelState {
    SysBusDevice parent_obj;

    MemoryRegion iomem[APPLE_MODERN_DOCKCHANNEL_WINDOWS];
    AppleModernDockChannelWindow win[APPLE_MODERN_DOCKCHANNEL_WINDOWS];
    qemu_irq irq;

    uint32_t fifo_size;     /* ADT fifo-size */
    uint32_t channel;       /* ADT channel-number */
    uint32_t irq_mask;
    uint32_t irq_flag;
    uint32_t tx_thresh;
    uint32_t rx_thresh;

    /* AP -> remote: counted, logged and handed to the peer if there is one. */
    uint64_t tx_total;
    uint32_t tx_logged;
    AppleModernDockChannelPeerTx peer_tx;
    void *peer_opaque;

    /* Remote -> AP: filled by apple_modern_dockchannel_push_rx(). */
    uint8_t rx[APPLE_MODERN_DOCKCHANNEL_FIFO_MAX];
    uint32_t rx_head;
    uint32_t rx_count;

    /* First access per (window, 32-bit slot, direction), for the access log. */
    unsigned long seen[APPLE_MODERN_DOCKCHANNEL_WINDOWS][2]
                      [BITS_TO_LONGS(APPLE_MODERN_DOCKCHANNEL_WIN_SIZE / 4)];
};

SysBusDevice *apple_modern_dockchannel_new(uint32_t fifo_size, uint32_t channel);

/* Queue bytes the remote side sends to the AP; false if they do not fit. */
bool apple_modern_dockchannel_push_rx(AppleModernDockChannelState *s,
                                      const uint8_t *data, size_t len);
/* Free space in the AP-bound FIFO. */
uint32_t apple_modern_dockchannel_rx_space(AppleModernDockChannelState *s);
/* Attach the far end; tx may be NULL to detach. */
void apple_modern_dockchannel_set_peer(AppleModernDockChannelState *s,
                                       AppleModernDockChannelPeerTx tx,
                                       void *opaque);

#endif
