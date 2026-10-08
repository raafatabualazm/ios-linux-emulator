/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_SLC_H
#define HW_ARM_APPLE_MODERN_MCC_SLC_H
#include "hw/arm/apple-silicon/modern-mcc-dsid.h"

/* AMCC reg[2] system-level-cache way control. The pinned BootKC's
 * mccEnableCacheMode (0xfffffff00982133c) writes the way count to global
 * +0x2800 (AMCC + 0x100000), then mccWaitForWaysPwrOn (0xfffffff009820fd4)
 * reads each plane's +0x2804 with no delay or timeout until bits [30:24]
 * ("Data Ways") and then bits [14:8] ("Tag Ways") equal that count, then
 * global +0x82c is written 0. The driver never names +0x82c.
 * cacheFlush (0xfffffff00982186c) writes global +0x82c = 1 and +0x2844 = 1
 * and polls each plane's +0x2844 while bit 0 is set. */
#define APPLE_MODERN_MCC_SLC_PLANES 4
#define APPLE_MODERN_MCC_SLC_PLANE_STRIDE 0x40000
#define APPLE_MODERN_MCC_SLC_GLOBAL_OFFSET 0x100000
#define APPLE_MODERN_MCC_SLC_WAYS 0x2800
#define APPLE_MODERN_MCC_SLC_WAY_STATUS 0x2804
#define APPLE_MODERN_MCC_SLC_CTRL_82C 0x82c
/* Handover state read back per plane on Macs with t604x/t8140-family MCCs
 * (m1n1 draft PR #664; the machine is not stated): +0x2800 = 0x8000000c,
 * +0x2804 = 0x0c000c00, i.e. 12 ways already enabled. The model keeps that
 * value in the write-only global way cell, so plane status reports 12 ways
 * from reset. Analogy for iPhone17,3; bit 31 is unexplained. */
#define APPLE_MODERN_MCC_SLC_RESET_WAYS 0x8000000cU
#define APPLE_MODERN_MCC_SLC_FLUSH 0x2844
#define APPLE_MODERN_MCC_SLC_WAY_MASK 0x7f
/* Views 0..2: global way count, +0x82c and flush request (write-only).
 * 3..6: plane way status, 7..10: plane flush status (read-only). */
#define APPLE_MODERN_MCC_SLC_GLOBAL_VIEWS 3
#define APPLE_MODERN_MCC_SLC_STATUS_VIEW 3
#define APPLE_MODERN_MCC_SLC_FLUSH_VIEW 7
#define APPLE_MODERN_MCC_SLC_VIEWS 11
#define APPLE_MODERN_MCC_SLC_SPAN 4

typedef struct AppleModernMCCSLCPlan {
    uint64_t addresses[APPLE_MODERN_MCC_SLC_VIEWS];
} AppleModernMCCSLCPlan;
typedef struct AppleModernMCCSLCCore {
    uint32_t ways, ctrl_82c, flush;
    uint64_t reads, writes;
} AppleModernMCCSLCCore;

/* Plane-0 views lie inside Darwin's compatibility AMCC aperture when the
 * served tree has one; the board excludes the whole aperture except the
 * views inside it and maps only those views above it. */
bool apple_modern_mcc_slc_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCSLCPlan *output, Error **errp);
/* AMCC-relative offset of a view; UINT64_MAX for an invalid view. */
uint64_t apple_modern_mcc_slc_view_offset(unsigned view);
/* QOM: requested-ways is the stored global +0x2800 value (the handover
 * value until the driver writes), control-82c and flush-request the last
 * stored +0x82c and +0x2844 values. */
void apple_modern_mcc_slc_core_reset(AppleModernMCCSLCCore *core);
/* Declared profile: the global writes broadcast to every plane at once and
 * requested ways report powered immediately, as ((ways & 0x7f) << 24) |
 * ((ways & 0x7f) << 8) (the echo itself matches PR #664's measurement);
 * flushes complete immediately (bit 0 reads 0). An aligned 64-bit access
 * that starts in the compatibility aperture at plane-0 +0x2800/+0x2840 is
 * served wholly by the aperture (measured); the driver uses 32-bit loads. */
bool apple_modern_mcc_slc_core_read(AppleModernMCCSLCCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value);
bool apple_modern_mcc_slc_core_write(AppleModernMCCSLCCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_MCC_SLC "apple-modern-mcc-slc"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMCCSLCState, APPLE_MODERN_MCC_SLC)
DeviceState *apple_modern_mcc_slc_new(void);
#endif
#endif
