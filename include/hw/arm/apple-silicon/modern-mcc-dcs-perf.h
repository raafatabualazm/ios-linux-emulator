/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_DCS_PERF_H
#define HW_ARM_APPLE_MODERN_MCC_DCS_PERF_H
#include "hw/arm/apple-silicon/modern-mcc-dramcfg.h"

#define APPLE_MODERN_DCS_PERF_VIEWS 8
#define APPLE_MODERN_DCS_PERF_CONTROLS 64
#define APPLE_MODERN_DCS_PERF_COUNTERS 14
#define APPLE_MODERN_DCS_PERF_CONTROL_OFFSET 0x580
#define APPLE_MODERN_DCS_PERF_COUNTER_OFFSET 0x4000

typedef struct AppleModernDCSPERFPlan {
    uint64_t addresses[APPLE_MODERN_DCS_PERF_VIEWS];
    uint64_t spans[APPLE_MODERN_DCS_PERF_VIEWS];
} AppleModernDCSPERFPlan;
typedef struct AppleModernDCSPERFCore {
    uint32_t controls[APPLE_MODERN_MCC_DCS_COUNT][APPLE_MODERN_DCS_PERF_CONTROLS];
    uint64_t values[APPLE_MODERN_MCC_DCS_COUNT][APPLE_MODERN_DCS_PERF_COUNTERS];
    uint64_t reset_value;
    uint64_t reads, writes, clears, event_updates;
} AppleModernDCSPERFCore;

bool apple_modern_dcs_perf_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDCSPERFPlan *output, Error **errp);
void apple_modern_dcs_perf_core_reset(AppleModernDCSPERFCore *core);
bool apple_modern_dcs_perf_core_read(AppleModernDCSPERFCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value);
bool apple_modern_dcs_perf_core_write(AppleModernDCSPERFCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value);
bool apple_modern_dcs_perf_core_event(AppleModernDCSPERFCore *core,
    unsigned bank, unsigned counter, uint64_t amount);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_DCS_PERF "apple-modern-mcc-dcs-perf"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernDCSPERFState, APPLE_MODERN_DCS_PERF)
DeviceState *apple_modern_dcs_perf_new(uint64_t reset_value);
#endif
#endif
