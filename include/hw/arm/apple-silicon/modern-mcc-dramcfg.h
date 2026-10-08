/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_DRAMCFG_H
#define HW_ARM_APPLE_MODERN_MCC_DRAMCFG_H
#include "hw/arm/apple-silicon/modern-board-regions.h"
#define APPLE_MODERN_MCC_DCS_COUNT 4
#define APPLE_MODERN_MCC_DRAMCFG_OFFSET 0x1d48
typedef struct AppleModernMCCDRAMCFGPlan {
    uint64_t addresses[APPLE_MODERN_MCC_DCS_COUNT];
} AppleModernMCCDRAMCFGPlan;
typedef struct AppleModernMCCDRAMCFGCore {
    uint32_t values[APPLE_MODERN_MCC_DCS_COUNT], reset_value;
    uint64_t reads, writes;
} AppleModernMCCDRAMCFGCore;
bool apple_modern_mcc_dramcfg_plan_build(AppleModernBlob dtree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCDRAMCFGPlan *output, Error **errp);
void apple_modern_mcc_dramcfg_core_reset(AppleModernMCCDRAMCFGCore *core);
bool apple_modern_mcc_dramcfg_core_read(AppleModernMCCDRAMCFGCore *core,
    unsigned bank, uint64_t offset, uint32_t *value);
bool apple_modern_mcc_dramcfg_core_write(AppleModernMCCDRAMCFGCore *core,
    unsigned bank, uint64_t offset, uint32_t value);
#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_MCC_DRAMCFG "apple-modern-mcc-dramcfg"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMCCDRAMCFGState, APPLE_MODERN_MCC_DRAMCFG)
DeviceState *apple_modern_mcc_dramcfg_new(uint32_t reset_value);
#endif
#endif
