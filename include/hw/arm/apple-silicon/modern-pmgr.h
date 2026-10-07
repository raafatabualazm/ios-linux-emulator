/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_PMGR_H
#define HW_ARM_APPLE_MODERN_PMGR_H

#include "hw/arm/apple-silicon/modern-board-regions.h"

#define APPLE_MODERN_PMGR_MAX_WINDOWS 16
#define APPLE_MODERN_PMGR_MAX_CELLS 512
#define APPLE_MODERN_PMGR_MAX_WINDOW UINT64_C(0x100000)
#define APPLE_MODERN_PMGR_MAX_TOTAL UINT64_C(0x400000)

typedef struct AppleModernPMGRWindow {
    uint64_t base, size;
} AppleModernPMGRWindow;

typedef struct AppleModernPMGRCell {
    uint32_t offset;
    uint16_t id;
    uint8_t window;
} AppleModernPMGRCell;

typedef struct AppleModernPMGRPlan {
    AppleModernPMGRWindow windows[APPLE_MODERN_PMGR_MAX_WINDOWS];
    AppleModernPMGRCell cells[APPLE_MODERN_PMGR_MAX_CELLS];
    uint32_t window_count, cell_count, virtual_count;
} AppleModernPMGRPlan;

typedef struct AppleModernPMGRCore {
    AppleModernPMGRPlan plan;
    uint32_t values[APPLE_MODERN_PMGR_MAX_CELLS];
    uint64_t reads, writes, unknown_reads, unknown_writes, transitions;
} AppleModernPMGRCore;

/*
 * Decode the T8140 ps-groups and 48-byte devices schema without modifying ADT.
 * Only eight-byte power-cell slots within referenced windows are mapped;
 * every real cell must fit a selected window. Virtual domains have no cell.
 * Reject aliases, wrapping ranges, duplicate cells and DRAM/cell overlaps.
 * Other devices may occupy window holes; no broad register-RAM is introduced.
 * Output must be separate from the inputs. Errors clear a disjoint output.
 */
bool apple_modern_pmgr_plan_build(AppleModernBlob dtree,
                                  uint64_t dram_base, uint64_t dram_size,
                                  const AppleModernAddressRange *exclusions,
                                  size_t exclusion_count,
                                  AppleModernPMGRPlan *output, Error **errp);
void apple_modern_pmgr_core_reset(AppleModernPMGRCore *core);
uint32_t apple_modern_pmgr_core_read(AppleModernPMGRCore *core,
                                    unsigned window, uint64_t offset);
void apple_modern_pmgr_core_write(AppleModernPMGRCore *core,
                                  unsigned window, uint64_t offset,
                                  uint32_t value);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_PMGR "apple-modern-pmgr"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernPMGRState, APPLE_MODERN_PMGR)
DeviceState *apple_modern_pmgr_new(const AppleModernPMGRPlan *plan);
#endif
#endif
