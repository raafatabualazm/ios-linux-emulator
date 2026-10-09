/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_PMGR_STORAGE_H
#define HW_ARM_APPLE_MODERN_PMGR_STORAGE_H
#include "hw/arm/apple-silicon/modern-board-regions.h"

/*
 * Declared register storage for the PMGR registers that ApplePMGR::start
 * programs after initDriver (pinned BootKC a36b9241, iPhone17,3 ADT).
 *
 * DECLARED, not attested hardware behaviour: every accepted 32-bit register is
 * plain zero-reset storage. It is a boot-progress diagnostic profile, never
 * calibration, and it models no counting, latching, clearing or ready bit.
 * What is attested is which registers the driver touches and how:
 *
 * Provider "perf-groups" (the only provider so far). The /arm-io/pmgr ADT node
 * carries two tables the driver copies verbatim (observed in guest memory at
 * this+0x6108 and this+0x6528, equal byte for byte to the ADT properties):
 *   perf-groups   36-byte records: u32 reg_index (into /arm-io/pmgr reg),
 *                 u32 base offset, u32 flags, u32 0x10, u32 3, u32 4, 3 x 0.
 *   perf-counters 64-byte records: u8 type, u8 flags, u16 id, u8 group,
 *                 u8 group2, 2 pad, u32 offset, u32 offset2, name[32...].
 * The routine at 0xfffffff0092b61ec (reached through the vtable slot at
 * +0x980 of AppleT8140PMGR from the start path at 0xfffffff00928cf20) walks
 * every counter whose group has flags bit 1 set and does a read-modify-write
 * of the 32-bit register group.base + counter.offset (helper
 * 0xfffffff0092cabc0: read, then set the group's bit (perf-groups word 5) and
 * clear its field (word 4), writing the result back): type 0, 2 and 4; type 1
 * does the same for offset and, when counter.flags bit 1 is set, a second
 * read-modify-write of group2.base + offset2; type 3 is skipped; any other type
 * panics (rejected here). A second loop (helper 0xfffffff0092cacd8)
 * read-modify-writes each such group's own base register (clear bit 0, set
 * bit 1). Neither routine polls or waits. Instance 0 only (this+0x631c is 1).
 * On the iPhone17,3 ADT the programmed groups are 6 (reg 3 =
 * PMGRCLKGEN_AON_TOP, base 0x7b800, 7 registers) and 7 (reg 1 = PMGR_AON, base
 * 0x34000, 70 registers).
 *
 * The plan lists exactly those registers (one window per programmed group); a
 * 4- or 8-byte access that touches any other slot is rejected, so the next
 * unmodelled register shows up as the next frontier. The machine announces the
 * first access to each register so a run shows which ones the guest touched.
 */
#define APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS 16
#define APPLE_MODERN_PMGR_STORAGE_MAX_SPAN 0x1000
#define APPLE_MODERN_PMGR_STORAGE_SLOTS (APPLE_MODERN_PMGR_STORAGE_MAX_SPAN / 4)
#define APPLE_MODERN_PMGR_STORAGE_MASKS (APPLE_MODERN_PMGR_STORAGE_SLOTS / 64)

typedef struct AppleModernPMGRStorageWindow {
    uint64_t address;
    uint32_t size;      /* multiple of 4, at most APPLE_MODERN_PMGR_STORAGE_MAX_SPAN */
    uint32_t group;     /* ADT perf-groups index the window came from */
    uint64_t valid[APPLE_MODERN_PMGR_STORAGE_MASKS]; /* bit per 4-byte register */
} AppleModernPMGRStorageWindow;

typedef struct AppleModernPMGRStoragePlan {
    AppleModernPMGRStorageWindow windows[APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS];
    uint32_t count, registers;
} AppleModernPMGRStoragePlan;

typedef struct AppleModernPMGRStorageCore {
    AppleModernPMGRStoragePlan plan;
    uint32_t values[APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS]
                   [APPLE_MODERN_PMGR_STORAGE_SLOTS];
    uint64_t touched[APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS]
                    [APPLE_MODERN_PMGR_STORAGE_MASKS];
    uint64_t reads, writes;
} AppleModernPMGRStorageCore;

/*
 * Derive the plan from the served ADT (never modified). Every window must lie
 * inside its /arm-io/pmgr reg window, outside DRAM and the exclusions, and not
 * overlap another window. Output must be disjoint from the inputs; any error
 * clears it. At least one programmed group is required.
 */
bool apple_modern_pmgr_storage_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernPMGRStoragePlan *output, Error **errp);
/* Zero the values, touched map and counters; the plan is kept. */
void apple_modern_pmgr_storage_core_reset(AppleModernPMGRStorageCore *core);
/* 4- or 8-byte naturally aligned accesses; every covered 4-byte slot must be a
 * listed register. Rejected accesses change nothing. */
bool apple_modern_pmgr_storage_core_read(AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t *value);
bool apple_modern_pmgr_storage_core_write(AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t value);
/* True once the 4-byte register containing offset was read or written. */
bool apple_modern_pmgr_storage_core_touched(const AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_PMGR_STORAGE "apple-modern-pmgr-storage"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernPMGRStorageState, APPLE_MODERN_PMGR_STORAGE)
/* The plan is copied into the device before realize. */
DeviceState *apple_modern_pmgr_storage_new(const AppleModernPMGRStoragePlan *plan);
#endif
#endif
