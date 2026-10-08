/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_PERF_H
#define HW_ARM_APPLE_MODERN_MCC_PERF_H
#include "hw/arm/apple-silicon/modern-board-regions.h"

#define APPLE_MODERN_MCC_PERF_BANKS 3
#define APPLE_MODERN_MCC_PERF_COUNTERS 8
#define APPLE_MODERN_MCC_PERF_VIEWS (APPLE_MODERN_MCC_PERF_BANKS * 2)
#define APPLE_MODERN_MCC_PERF_CONTROL_OFFSET 0x28000
#define APPLE_MODERN_MCC_PERF_COUNTER_OFFSET 0x29000
#define APPLE_MODERN_MCC_PERF_BANK_STRIDE 0x40000
#define APPLE_MODERN_MCC_PERF_COUNTER_SPAN (APPLE_MODERN_MCC_PERF_COUNTERS * 8)

/* Each bank has an 8-byte control view followed by a 64-byte counter view.
 * Counter reset, modulo-64 addition and enable gating are a declared virtual
 * profile. No CPU/cache/bus traffic producer is connected by this module. */
typedef struct AppleModernMCCPerfPlan {
    uint64_t addresses[APPLE_MODERN_MCC_PERF_VIEWS];
} AppleModernMCCPerfPlan;
typedef struct AppleModernMCCPerfCore {
    uint64_t controls[APPLE_MODERN_MCC_PERF_BANKS];
    uint64_t values[APPLE_MODERN_MCC_PERF_BANKS][APPLE_MODERN_MCC_PERF_COUNTERS];
    uint64_t reset_value;
    uint64_t reads, writes, event_updates;
} AppleModernMCCPerfCore;

bool apple_modern_mcc_perf_plan_build(AppleModernBlob dtree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCPerfPlan *output, Error **errp);
void apple_modern_mcc_perf_core_reset(AppleModernMCCPerfCore *core);
bool apple_modern_mcc_perf_core_read(AppleModernMCCPerfCore *core,
    unsigned view, uint64_t offset, uint64_t *value);
bool apple_modern_mcc_perf_core_write(AppleModernMCCPerfCore *core,
    unsigned view, uint64_t offset, uint64_t value);
/* An event source must select an established channel. Valid disabled channels
 * discard events. MMIO reads and host time do not manufacture counter events. */
bool apple_modern_mcc_perf_core_event(AppleModernMCCPerfCore *core,
    unsigned bank, unsigned counter, uint64_t amount);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_MCC_PERF "apple-modern-mcc-perf"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMCCPerfState, APPLE_MODERN_MCC_PERF)
DeviceState *apple_modern_mcc_perf_new(uint64_t reset_value);
bool apple_modern_mcc_perf_event(DeviceState *dev, unsigned bank,
                                  unsigned counter, uint64_t amount);
#endif
#endif
