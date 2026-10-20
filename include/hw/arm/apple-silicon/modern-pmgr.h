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

/* PS_ACTIVE: TARGET 0xf and ACTUAL 0xf, what a domain iBoot left on reads as. */
#define APPLE_MODERN_PMGR_ACTIVE 0xffu

typedef struct AppleModernPMGRPlan {
    AppleModernPMGRWindow windows[APPLE_MODERN_PMGR_MAX_WINDOWS];
    AppleModernPMGRCell cells[APPLE_MODERN_PMGR_MAX_CELLS];
    uint32_t window_count, cell_count, virtual_count;
    /* Cells that reset to PS_ACTIVE instead of power-gated (default: none). */
    uint8_t boot_on[APPLE_MODERN_PMGR_MAX_CELLS];
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
/*
 * Mark hardware domains, by their ADT device-record names (16-byte field at
 * record +32, compared case-insensitively), as powered on at reset. Every
 * name must match exactly one hardware (non-virtual) record that has a cell,
 * and no cell may be named twice. On error the plan is unchanged.
 */
bool apple_modern_pmgr_plan_set_boot_on(AppleModernBlob dtree,
                                        AppleModernPMGRPlan *plan,
                                        const char *const *names, size_t count,
                                        Error **errp);
/*
 * Declared reset profile 'j700': the 25 domains Asahi's T8140 (A18 Pro,
 * MacBook Neo) PMGR device tree marks apple,always-on. ANALOGY for
 * iPhone17,3: all 25 names exist once in the iPhone ADT, but whether iBoot
 * leaves each of them on there is not attested. NULL (count 0) if unknown.
 */
const char *const *apple_modern_pmgr_boot_on_profile(const char *name,
                                                     size_t *count);
void apple_modern_pmgr_core_reset(AppleModernPMGRCore *core);
uint32_t apple_modern_pmgr_core_read(AppleModernPMGRCore *core,
                                    unsigned window, uint64_t offset);
void apple_modern_pmgr_core_write(AppleModernPMGRCore *core,
                                  unsigned window, uint64_t offset,
                                  uint32_t value);
bool apple_modern_pmgr_core_enable_site(AppleModernBlob dtree,
                                        const AppleModernPMGRPlan *plan,
                                        unsigned *window, uint32_t *offset,
                                        Error **errp);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_PMGR "apple-modern-pmgr"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernPMGRState, APPLE_MODERN_PMGR)
DeviceState *apple_modern_pmgr_new(const AppleModernPMGRPlan *plan);
/*
 * Default-off observability: log every power-cell access with the domain's
 * ADT device name (ECPU_0, PCPU_1, ...). Call before realize. Names are read
 * from the same /arm-io/pmgr "devices" table the plan was built from; the ADT
 * is not modified and no cell behaviour changes.
 *
 * This is how the guest's own core-enable write is identified: /cpus/cpuN
 * carries function-enable_core = [phandle, 'Core', 1 << cpu-id] pointing at
 * /arm-io/pmgr, and the six cores appear in that table as the non-virtual
 * domains ECPU_0..ECPU_3 and PCPU_0..PCPU_1.
 */
void apple_modern_pmgr_set_trace(DeviceState *dev, AppleModernBlob dtree);

/*
 * MISC_CORES, the register the guest actually uses to start a CPU core.
 *
 * It is NOT a power-state cell. ApplePMGR reaches it as
 *   cpu_start -> IOPMGR::enableCPUCore -> AbstractPMGR::enableCPUCore
 *   (mask = 1 << cpu-id) -> enableCPUCores -> ApplePMGR::configMiscCores
 *   -> a 32-bit store at regmap base + offset,
 * where AppleT8140PMGR binds the register group MISC_CORES to RegMap 0x69
 * (PMGR_SOC_MISC) at +0x4000, and RegMap 0x69 to /arm-io/pmgr `reg` entry
 * 0x18. On the served d47ap tree that is physical 0x300734000, inside
 * ps-group 0's window, so it falls in a hole between power cells and would
 * otherwise reach no callback at all.
 *
 * Writes are fire-and-forget: enable is +4, disable +0, per-cluster +8 + 4*n,
 * each a bitmask whose bit N is ADT cpu-id N. The driver performs no
 * completion read on this register group, so nothing has to be presented back.
 *
 * `site` locates the register from the ADT rather than hardcoding an address.
 * `callback` is invoked once per core bit set by an enable write.
 */
typedef void (*AppleModernPMGRCoreEnable)(void *opaque, unsigned core);
void apple_modern_pmgr_set_core_enable(DeviceState *dev, unsigned window,
                                       uint32_t offset,
                                       AppleModernPMGRCoreEnable callback,
                                       void *opaque);
#endif
#endif
