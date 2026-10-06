/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_AMCC_H
#define HW_ARM_APPLE_MODERN_AMCC_H

/*
 * Compatibility AMCC aperture, ported from Darwin-VM qemu-sptm 2867d847
 * (hw/arm/apple_amcc.c). The served ADT (Darwin's dt_fixup.py output) gives
 * the aperture address and each amcc-ctrr-{a,b,c,d} bank's lower/upper
 * limit register offsets. Only those bound registers are stored; every other
 * offset reads zero and ignores writes, so enable/write-disable/lock fields
 * (all at offset 0 in the served ADT) never read back as set. The real AMCC
 * enforces CTRR protection; this model enforces nothing.
 */
#define APPLE_MODERN_AMCC_BANKS         4
#define APPLE_MODERN_AMCC_BANK_C        2

#include "system/memory.h"

typedef struct AppleModernAMCC {
    MemoryRegion iomem;
    uint64_t base, size;
    uint32_t lwr_reg[APPLE_MODERN_AMCC_BANKS];
    uint32_t upr_reg[APPLE_MODERN_AMCC_BANKS];
    uint64_t ctrr_lwr[APPLE_MODERN_AMCC_BANKS];
    uint64_t ctrr_upr[APPLE_MODERN_AMCC_BANKS];
} AppleModernAMCC;

/*
 * Configure from validated ADT values and map the aperture. Offsets of zero
 * mean the bank has no bound registers. Nonzero offsets must be 8-byte
 * aligned, inside the aperture and distinct.
 */
bool apple_modern_amcc_init(AppleModernAMCC *amcc, MemoryRegion *parent,
                            uint64_t base, uint64_t size,
                            const uint32_t lwr_reg[APPLE_MODERN_AMCC_BANKS],
                            const uint32_t upr_reg[APPLE_MODERN_AMCC_BANKS],
                            Error **errp);
/* Clear all stored bounds. */
void apple_modern_amcc_reset(AppleModernAMCC *amcc);
/* Preload one bank's CTRR bounds (Darwin: bank C, from the memory map). */
void apple_modern_amcc_set_bounds(AppleModernAMCC *amcc, unsigned bank,
                                  uint64_t lower, uint64_t upper);

#endif
