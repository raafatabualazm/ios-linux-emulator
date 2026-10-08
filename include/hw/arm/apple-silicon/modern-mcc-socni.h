/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_SOCNI_H
#define HW_ARM_APPLE_MODERN_MCC_SOCNI_H
#include "hw/arm/apple-silicon/modern-board-regions.h"

#define APPLE_MODERN_MCC_SOCNI_BANKS 3
#define APPLE_MODERN_MCC_SOCNI_MAX_COUNTERS 36
#define APPLE_MODERN_MCC_SOCNI_TOTAL_COUNTERS 102
#define APPLE_MODERN_MCC_SOCNI_VIEWS 6
#define APPLE_MODERN_MCC_SOCNI_COUNTER_OFFSET 0x4000

/* Each bank owns only its observed contiguous controls and counters. */
typedef struct AppleModernMCCSocniPlan {
    uint64_t addresses[APPLE_MODERN_MCC_SOCNI_VIEWS];
    uint64_t spans[APPLE_MODERN_MCC_SOCNI_VIEWS];
} AppleModernMCCSocniPlan;
typedef struct AppleModernMCCSocniCore {
    uint32_t controls[APPLE_MODERN_MCC_SOCNI_BANKS][APPLE_MODERN_MCC_SOCNI_MAX_COUNTERS];
    uint64_t values[APPLE_MODERN_MCC_SOCNI_BANKS][APPLE_MODERN_MCC_SOCNI_MAX_COUNTERS];
    uint64_t reset_value;
    uint64_t reads, writes, event_updates;
    bool commands_required;
    uint32_t active_banks;
} AppleModernMCCSocniCore;

unsigned apple_modern_mcc_socni_counter_count(unsigned bank);
uint64_t apple_modern_mcc_socni_view_span(unsigned view);
bool apple_modern_mcc_socni_plan_build(AppleModernBlob dtree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCSocniPlan *output, Error **errp);
void apple_modern_mcc_socni_core_reset(AppleModernMCCSocniCore *core);
bool apple_modern_mcc_socni_core_read(AppleModernMCCSocniCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value);
bool apple_modern_mcc_socni_core_write(AppleModernMCCSocniCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value);
/* Enable gating and modulo-64 addition are declared virtual choices. No
 * physical event producer is connected, and MMIO reads do not count events. */
bool apple_modern_mcc_socni_core_event(AppleModernMCCSocniCore *core,
    unsigned bank, unsigned counter, uint64_t amount);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_MCC_SOCNI "apple-modern-mcc-socni"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMCCSocniState, APPLE_MODERN_MCC_SOCNI)
DeviceState *apple_modern_mcc_socni_new(uint64_t reset_value);
bool apple_modern_mcc_socni_event(DeviceState *dev, unsigned bank,
                                 unsigned counter, uint64_t amount);
/* Called during board construction, before CPUs run. */
AppleModernMCCSocniCore *apple_modern_mcc_socni_attach_commands(DeviceState *dev);
#endif
#endif
