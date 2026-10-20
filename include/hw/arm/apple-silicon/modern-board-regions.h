/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_BOARD_REGIONS_H
#define HW_ARM_APPLE_MODERN_BOARD_REGIONS_H

#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/*
 * Boot-CPU policy uses 2 windows. Serving every ADT core needs 8 on d47ap:
 * six distinct cpu-impl-reg plus the two shared cpm-impl-reg (cpu0-3 name one,
 * cpu4-5 the other). 16 leaves headroom for a wider tree.
 */
#define APPLE_MODERN_CPU_REGISTER_WINDOWS 16
/* ADT cores considered under the all-cores policy. */
#define APPLE_MODERN_BOARD_REGION_MAX_CORES 6
/* The full declared apple-modern profile appends at most 68 spans. PMGR
 * storage on this tree places about 46 more (counter table plus fixed
 * windows; owners such as disp0 reg[5] omit some). 256 covers that stack. */
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
 * Which cores' register windows to back.
 *
 * BOOT_CPU is the long-standing behaviour and the default: cpu0's
 * cpu-impl-reg then cpm-impl-reg, two windows with their original names, so a
 * single-CPU board sees exactly the memory map it always has.
 *
 * ALL_CORES additionally backs every other /cpus/cpuN window the tree names,
 * deduplicated, because several cores share one cpm-impl-reg. A secondary
 * core faults on an unbacked window (unassigned access raises an external
 * abort here, it does not read as zero), and the P-cluster cpm window is also
 * where the PMGR driver's own register ladder reaches.
 */
typedef enum AppleModernBoardRegionPolicy {
    APPLE_MODERN_BOARD_REGIONS_BOOT_CPU = 0,
    APPLE_MODERN_BOARD_REGIONS_ALL_CORES,
} AppleModernBoardRegionPolicy;

/*
 * Describe Darwin-VM's zeroed-RAM compatibility windows for the selected
 * cores' absolute cpu-impl-reg and cpm-impl-reg properties. Each supported property must be
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
                                     AppleModernBoardRegionPolicy policy,
                                     AppleModernBoardRegions *output,
                                     Error **errp);

#endif
