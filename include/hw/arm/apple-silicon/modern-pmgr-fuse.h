/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_PMGR_FUSE_H
#define HW_ARM_APPLE_MODERN_PMGR_FUSE_H
#include "hw/arm/apple-silicon/modern-pmgr.h"
#define APPLE_MODERN_PMGR_FUSE_SIZE 0x4000
#define APPLE_MODERN_PMGR_FUSE_BASE UINT64_C(0x3082c8000)
typedef struct AppleModernPMGRFusePlan {
    uint64_t base, size;
} AppleModernPMGRFusePlan;
typedef struct AppleModernPMGRFuseCore {
    uint8_t image[APPLE_MODERN_PMGR_FUSE_SIZE];
    bool loaded;
    uint64_t reads, rejected_writes;
} AppleModernPMGRFuseCore;
bool apple_modern_pmgr_fuse_plan_build(AppleModernBlob dtree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernPMGRFusePlan *output, Error **errp);
bool apple_modern_pmgr_fuse_core_load(AppleModernPMGRFuseCore *core,
                                      AppleModernBlob image, Error **errp);
bool apple_modern_pmgr_fuse_core_read(AppleModernPMGRFuseCore *core,
                                      uint64_t offset, uint32_t *value);
void apple_modern_pmgr_fuse_core_reset(AppleModernPMGRFuseCore *core);
#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_PMGR_FUSE "apple-modern-pmgr-fuse"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernPMGRFuseState, APPLE_MODERN_PMGR_FUSE)
DeviceState *apple_modern_pmgr_fuse_new(AppleModernBlob image, Error **errp);
#endif
#endif
