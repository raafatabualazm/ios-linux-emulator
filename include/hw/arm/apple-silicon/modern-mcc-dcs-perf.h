/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_DCS_PERF_H
#define HW_ARM_APPLE_MODERN_MCC_DCS_PERF_H
#include "hw/arm/apple-silicon/modern-mcc-dramcfg.h"

/* The pinned BootKC's DCS performance descriptors (39, table
 * 0xfffffff00b923020) name DCS units 0..2 only; unit 3 has no perf access. */
#define APPLE_MODERN_DCS_PERF_BANKS 3
#define APPLE_MODERN_DCS_PERF_VIEWS (APPLE_MODERN_DCS_PERF_BANKS * 2)
/* Per bank: +0x580 command, +0x584 event enable, +0x588 duration
 * enable/clear, +0x58c duration select, then 10 x 6 parameter words at
 * +0x590 + 0x18 * channel (driver constants {0x590, 0x18}). */
#define APPLE_MODERN_DCS_PERF_CONTROLS 64
#define APPLE_MODERN_DCS_PERF_EVENTS 10
#define APPLE_MODERN_DCS_PERF_DURATIONS 4
#define APPLE_MODERN_DCS_PERF_COUNTERS \
    (APPLE_MODERN_DCS_PERF_EVENTS + APPLE_MODERN_DCS_PERF_DURATIONS)
#define APPLE_MODERN_DCS_PERF_CONTROL_OFFSET 0x580
#define APPLE_MODERN_DCS_PERF_COUNTER_OFFSET 0x4000
#define APPLE_MODERN_DCS_PERF_COMMAND 0x0
#define APPLE_MODERN_DCS_PERF_EVENT_ENABLE 0x4
#define APPLE_MODERN_DCS_PERF_DURATION_CONTROL 0x8
#define APPLE_MODERN_DCS_PERF_DURATION_SELECT 0xc
/* +0x588: enable bit 4*i, "clear bit" 16+4*i for duration counter i. */
#define APPLE_MODERN_DCS_PERF_CLEAR_BITS 0x11110000U

typedef struct AppleModernDCSPERFPlan {
    uint64_t addresses[APPLE_MODERN_DCS_PERF_VIEWS];
    uint64_t spans[APPLE_MODERN_DCS_PERF_VIEWS];
} AppleModernDCSPERFPlan;
typedef struct AppleModernDCSPERFCore {
    uint32_t controls[APPLE_MODERN_DCS_PERF_BANKS][APPLE_MODERN_DCS_PERF_CONTROLS];
    uint64_t values[APPLE_MODERN_DCS_PERF_BANKS][APPLE_MODERN_DCS_PERF_COUNTERS];
    uint64_t reset_value;
    uint64_t reads, writes, clears, event_updates;
} AppleModernDCSPERFCore;

bool apple_modern_dcs_perf_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDCSPERFPlan *output, Error **errp);
void apple_modern_dcs_perf_core_reset(AppleModernDCSPERFCore *core);
/* Even views are 64 x 32-bit controls, odd views 14 x 64-bit counters. */
bool apple_modern_dcs_perf_core_read(AppleModernDCSPERFCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value);
/* Declared functional profile, beyond the driver's attested accesses:
 * controls store all 32 bits, except that the +0x588 clear bits complete
 * at once, read as zero and zero their duration counter (inferred; a second
 * restore without a quiesce in between therefore restarts the driver's
 * duration totals). Counters are read-only. The command register has no
 * modelled effect. DCS2 provides ten event channels although the driver
 * uses 0..6. Non-native widths and alignments abort, except that QEMU
 * splits an aligned 64-bit access to these sub-page control views into two
 * 32-bit accesses (measured); the driver only uses 32-bit control helpers. */
bool apple_modern_dcs_perf_core_write(AppleModernDCSPERFCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value);
/* Virtual event input (no producer is connected): counters advance only
 * while enabled, events by +0x584 bit i, durations by +0x588 bit 4*i. */
bool apple_modern_dcs_perf_core_event(AppleModernDCSPERFCore *core,
    unsigned bank, unsigned counter, uint64_t amount);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_DCS_PERF "apple-modern-mcc-dcs-perf"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernDCSPERFState, APPLE_MODERN_DCS_PERF)
DeviceState *apple_modern_dcs_perf_new(uint64_t reset_value);
bool apple_modern_dcs_perf_event(DeviceState *dev, unsigned bank,
                                 unsigned counter, uint64_t amount);
#endif
#endif
