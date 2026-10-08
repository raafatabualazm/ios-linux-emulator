/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_DSID_H
#define HW_ARM_APPLE_MODERN_MCC_DSID_H
#include "hw/arm/apple-silicon/modern-mcc-quota.h"

/* AMCC reg[2] DSID profile block, per plane (plane << 18). The pinned
 * BootKC's enableDsidProfileCounters (0xfffffff009825a7c) writes +0x2a010
 * on the first plane only, then +0x2e000, +0x2a008 and +0x2a000 on each of
 * four planes. Perf slot 3 samples "DSID 0 Hits"/"DSID 0 Misses" at
 * +0x2a058 + 8 * ch on plane 0 only. Only those cells are mapped. */
#define APPLE_MODERN_MCC_DSID_PLANES 4
#define APPLE_MODERN_MCC_AMCC_SPAN 0x140000
#define APPLE_MODERN_MCC_DSID_PLANE_STRIDE 0x40000
#define APPLE_MODERN_MCC_DSID_CONTROL_OFFSET 0x2a000
#define APPLE_MODERN_MCC_DSID_INTERVAL_OFFSET 0x2e000
#define APPLE_MODERN_MCC_DSID_COUNTER_OFFSET 0x2a058
#define APPLE_MODERN_MCC_DSID_CONTROLS 3
#define APPLE_MODERN_MCC_DSID_COUNTERS 2
/* Views 0..3: plane controls (64-bit), 4..7: plane intervals (32-bit),
 * 8: plane-0 counters (64-bit, read-only). */
#define APPLE_MODERN_MCC_DSID_INTERVAL_VIEW 4
#define APPLE_MODERN_MCC_DSID_COUNTER_VIEW 8
#define APPLE_MODERN_MCC_DSID_VIEWS 9

typedef struct AppleModernMCCDSIDPlan {
    uint64_t addresses[APPLE_MODERN_MCC_DSID_VIEWS];
    uint64_t spans[APPLE_MODERN_MCC_DSID_VIEWS];
} AppleModernMCCDSIDPlan;
typedef struct AppleModernMCCDSIDCore {
    uint64_t controls[APPLE_MODERN_MCC_DSID_PLANES][APPLE_MODERN_MCC_DSID_CONTROLS];
    uint32_t intervals[APPLE_MODERN_MCC_DSID_PLANES];
    uint64_t values[APPLE_MODERN_MCC_DSID_COUNTERS];
    uint64_t reset_value;
    uint64_t reads, writes, event_updates;
} AppleModernMCCDSIDCore;

uint64_t apple_modern_mcc_dsid_view_span(unsigned view);
bool apple_modern_mcc_dsid_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCDSIDPlan *output, Error **errp);
void apple_modern_mcc_dsid_core_reset(AppleModernMCCDSIDCore *core);
/* Declared profile: controls and intervals store and read back the last
 * written value; no side effect is attested. Counters are read-only and
 * start at the declared reset value. */
bool apple_modern_mcc_dsid_core_read(AppleModernMCCDSIDCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value);
bool apple_modern_mcc_dsid_core_write(AppleModernMCCDSIDCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value);
/* Virtual event input (no producer is connected): counters advance only
 * while plane 0's +0x2a000 bit 0 ("counter Enable") is set (inferred; bit 4,
 * written only on the first plane, is an equally plausible gate). */
bool apple_modern_mcc_dsid_core_event(AppleModernMCCDSIDCore *core,
    unsigned counter, uint64_t amount);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_MCC_DSID "apple-modern-mcc-dsid"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMCCDSIDState, APPLE_MODERN_MCC_DSID)
DeviceState *apple_modern_mcc_dsid_new(uint64_t reset_value);
bool apple_modern_mcc_dsid_event(DeviceState *dev, unsigned counter,
                                 uint64_t amount);
#endif
#endif
