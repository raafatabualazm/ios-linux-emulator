/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_SMC_H
#define HW_ARM_APPLE_MODERN_SMC_H
#include "hw/arm/apple-silicon/modern-board-regions.h"
/* Geometry is read from the served ADT and must match T8140 stock lengths.
 * The peer reuses the legacy SMC key protocol: an analogy, not modern firmware.
 * Core bit 0 and pre-loaded/running are declared host-simulated firmware claims.
 * Timers have no implemented semantics; accesses are logged and return zero.
 * No touch transport or modern button-notification ABI is claimed here. */
#define APPLE_MODERN_SMC_WINDOWS 4
#define APPLE_MODERN_SMC_IRQS 4
typedef struct AppleModernSMCPlan {
    uint64_t address[APPLE_MODERN_SMC_WINDOWS]; /* wrapper, core, timers, SRAM */
    uint64_t size[APPLE_MODERN_SMC_WINDOWS];
    uint32_t interrupts[APPLE_MODERN_SMC_IRQS];
} AppleModernSMCPlan;
bool apple_modern_smc_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernSMCPlan *out, Error **errp);
const AppleModernAdtOverride *apple_modern_smc_overrides(size_t *count);
#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
SysBusDevice *apple_modern_smc_new(const AppleModernSMCPlan *plan);
#endif
#endif
