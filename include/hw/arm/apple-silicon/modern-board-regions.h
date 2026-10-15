/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_BOARD_REGIONS_H
#define HW_ARM_APPLE_MODERN_BOARD_REGIONS_H

#include "hw/arm/apple-silicon/modern-boot-metadata.h"

#define APPLE_MODERN_CPU_REGISTER_WINDOWS 2
/* Combined MCC, 56-window PMGR storage, and DCP tracing exceed the earlier
 * 128-span budget. Keep a fixed bound for the complete merged profile; every
 * planner still refuses an exclusion count beyond it. */
#define APPLE_MODERN_MAX_BOARD_EXCLUSIONS 256
#define APPLE_MODERN_MAX_REGISTER_WINDOW (UINT64_C(1) << 20)
#define APPLE_MODERN_MAX_REGISTER_TOTAL (UINT64_C(2) << 20)

typedef struct AppleModernAddressRange {
    uint64_t physical_address;
    uint64_t size;
} AppleModernAddressRange;

typedef struct AppleModernBoardRegion {
    char name[32];
    uint64_t physical_address;
    uint64_t size;
} AppleModernBoardRegion;

typedef struct AppleModernBoardRegions {
    AppleModernBoardRegion windows[APPLE_MODERN_CPU_REGISTER_WINDOWS];
    size_t count;
    uint64_t total_size;
} AppleModernBoardRegions;

/*
 * Describe Darwin-VM's zeroed-RAM compatibility windows for cpu0's absolute
 * cpu-impl-reg and cpm-impl-reg properties. Each supported property must be
 * exactly one little-endian (base, size) tuple. Additional tuples are rejected
 * rather than silently ignored. This is register storage, not an implementation
 * of hardware side effects, locks or protection. Never modifies the ADT.
 *
 * The caller supplies every other mapped register span (including UART) as an
 * exclusion; DRAM is checked separately. All spans must be nonempty and not
 * wrap, and windows must not overlap each other, DRAM or any exclusion.
 * Output must be fresh and disjoint from the ADT/exclusions. Forbidden aliases
 * are rejected without writing output; other failures clear output. The board
 * owns allocation and restores these logical spans to zero on reset.
 */
bool apple_modern_board_regions_build(AppleModernBlob dtree,
                                     uint64_t dram_base, uint64_t dram_size,
                                     const AppleModernAddressRange *exclusions,
                                     size_t exclusion_count,
                                     AppleModernBoardRegions *output,
                                     Error **errp);

#endif
