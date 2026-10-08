/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_QUOTA_H
#define HW_ARM_APPLE_MODERN_MCC_QUOTA_H
#include "hw/arm/apple-silicon/modern-board-regions.h"
#define APPLE_MODERN_MCC_QUOTA_PLANES 4
#define APPLE_MODERN_MCC_QUOTA_GROUPS 32
#define APPLE_MODERN_MCC_QUOTA_VIEWS 5
#define APPLE_MODERN_MCC_QUOTA_GLOBAL 4
#define APPLE_MODERN_MCC_QUOTA_SPAN (APPLE_MODERN_MCC_QUOTA_GROUPS * 4)
#define APPLE_MODERN_MCC_QUOTA_OFFSET 0xa000
#define APPLE_MODERN_MCC_QUOTA_PLANE_STRIDE 0x40000
#define APPLE_MODERN_MCC_QUOTA_GLOBAL_OFFSET 0x100000
typedef struct AppleModernMCCQuotaPlan {
    uint64_t addresses[APPLE_MODERN_MCC_QUOTA_VIEWS];
} AppleModernMCCQuotaPlan;
typedef struct AppleModernMCCQuotaCore {
    uint32_t values[APPLE_MODERN_MCC_QUOTA_PLANES][APPLE_MODERN_MCC_QUOTA_GROUPS];
    uint32_t reset_value;
    uint64_t reads, writes, broadcast_writes;
} AppleModernMCCQuotaCore;
bool apple_modern_mcc_quota_plan_build(AppleModernBlob dtree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCQuotaPlan *output, Error **errp);
void apple_modern_mcc_quota_core_reset(AppleModernMCCQuotaCore *core);
bool apple_modern_mcc_quota_core_read(AppleModernMCCQuotaCore *core,
    unsigned view, uint64_t offset, uint32_t *value);
bool apple_modern_mcc_quota_core_write(AppleModernMCCQuotaCore *core,
    unsigned view, uint64_t offset, uint32_t value);
#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_MCC_QUOTA "apple-modern-mcc-quota"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMCCQuotaState, APPLE_MODERN_MCC_QUOTA)
DeviceState *apple_modern_mcc_quota_new(uint32_t reset_value);
#endif
#endif
