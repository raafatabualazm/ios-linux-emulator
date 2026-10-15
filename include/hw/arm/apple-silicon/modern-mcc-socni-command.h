/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_MCC_SOCNI_COMMAND_H
#define HW_ARM_APPLE_MODERN_MCC_SOCNI_COMMAND_H
#include "hw/arm/apple-silicon/modern-mcc-socni.h"

#define APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS 3
#define APPLE_MODERN_MCC_SOCNI_COMMAND_SPAN 4
#define APPLE_MODERN_MCC_SOCNI_COMMAND_OFFSET 0x100
#define APPLE_MODERN_MCC_SOCNI_COMMAND_RESTORE 1

typedef struct AppleModernMCCSocniCommandPlan {
    uint64_t addresses[APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS];
} AppleModernMCCSocniCommandPlan;
typedef struct AppleModernMCCSocniCommandCore {
    uint64_t writes;
    uint64_t requests[APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS];
} AppleModernMCCSocniCommandCore;

bool apple_modern_mcc_socni_command_plan_build(AppleModernBlob dtree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCSocniCommandPlan *output, Error **errp);
void apple_modern_mcc_socni_command_core_reset(AppleModernMCCSocniCommandCore *core);
bool apple_modern_mcc_socni_command_core_read(AppleModernMCCSocniCommandCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value);
/* Records a restore request only: no effective enable, clear or readiness. */
bool apple_modern_mcc_socni_command_core_write(AppleModernMCCSocniCommandCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_MCC_SOCNI_COMMAND "apple-modern-mcc-socni-command"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMCCSocniCommandState, APPLE_MODERN_MCC_SOCNI_COMMAND)
DeviceState *apple_modern_mcc_socni_command_new(void);
#endif
#endif
