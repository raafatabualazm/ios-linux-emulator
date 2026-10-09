/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_CPU_DVFM_H
#define HW_ARM_APPLE_MODERN_CPU_DVFM_H
#include "hw/arm/apple-silicon/modern-board-regions.h"

/*
 * Per-cluster CPU DVFM windows as ApplePMGR reads them (pinned BootKC a36b9241).
 *
 * Windows 0 and 1, the state tables. AppleT8140PMGR's reader at
 * 0xfffffff009848900 forms the offset 0xe78008 + state * 0x40 from the cluster
 * base, loads 64 bits and returns bits [42:38]; sibling readers (0xfffffff009848618
 * and its neighbours) use other fields of the same entries. The E cluster table
 * starts at 0x210e78000 and the P cluster table at 0x211e78000 (the cluster
 * stride is 0x1000000, as for cpu-impl-reg 0x210050000 / 0x211050000).
 *
 * Windows 2 and 3, the DVFM control page (RegMap E_ACC_CPM_DVFM selector 12 at
 * 0x210e70000 and P_ACC0_CPM_DVFM selector 24 at 0x211e70000, 0x1000 bytes). The
 * attested reads are only these 64-bit registers: +0xa8 and +0xd0 in the E
 * cluster, +0xa8, +0xb0, +0xd0 and +0xd8 in the P cluster. The reader that
 * loops over them (0xfffffff0092ca800, reached through the AppleT8140PMGR
 * thunk at 0xfffffff0098486f8 from the DVMR weight publisher at
 * 0xfffffff0092a3000) takes each register as nine packed 5-bit fields
 * (bits 5*j+4:5*j, j = 0..8) and compares each field with a requested DVFM state
 * index; a match contributes the field's id byte to a returned set that the
 * driver publishes as the DVMRWeights and DVMRWeightTypes properties. The
 * driver never writes these registers.
 *
 * In every window the driver only reads and republishes the values. DECLARED,
 * not attested: the registers hold zero; the real contents are per-chip
 * firmware-written entries (frequencies, voltage ids and the field values
 * above); none is available for this device, so this is a boot-progress
 * diagnostic profile, not calibration or silicon behaviour.
 *
 * Windows 0 and 1 (state tables) accept every aligned 4-byte and 8-byte access
 * and keep what is written. Windows 2 and 3 (control pages) accept ONLY the
 * attested 8-byte reads named above, which return zero; writes, 4-byte
 * accesses and every other offset of the page fault, so an unattested access
 * shows up as the next frontier instead of being absorbed. The machine logs
 * the first access to each 8-byte word so a run shows which words the guest
 * really touched.
 */
#define APPLE_MODERN_DVFM_WINDOWS 4
/* Windows [0, TABLE_WINDOWS) are state tables; the rest are control pages. */
#define APPLE_MODERN_DVFM_TABLE_WINDOWS 2
#define APPLE_MODERN_DVFM_SPAN 0x1000
#define APPLE_MODERN_DVFM_WORDS (APPLE_MODERN_DVFM_SPAN / 8)

typedef struct AppleModernDVFMPlan {
    uint64_t addresses[APPLE_MODERN_DVFM_WINDOWS];
} AppleModernDVFMPlan;
typedef struct AppleModernDVFMCore {
    uint64_t words[APPLE_MODERN_DVFM_WINDOWS][APPLE_MODERN_DVFM_WORDS];
    /* One bit per 8-byte word: set by the first successful read or write. */
    uint64_t touched[APPLE_MODERN_DVFM_WINDOWS][APPLE_MODERN_DVFM_WORDS / 64];
    uint64_t reads, writes;
} AppleModernDVFMCore;

/* Windows lie in the arm-io range at E 0x210e78000, P 0x211e78000, E 0x210e70000
 * and P 0x211e70000 (matched against /arm-io ranges and the T8140 cpu node
 * geometry; the planner also rejects any overlap among them). */
bool apple_modern_cpu_dvfm_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDVFMPlan *output, Error **errp);
void apple_modern_cpu_dvfm_core_reset(AppleModernDVFMCore *core);
bool apple_modern_cpu_dvfm_core_read(AppleModernDVFMCore *core, unsigned window,
    uint64_t offset, unsigned size, uint64_t *value);
bool apple_modern_cpu_dvfm_core_write(AppleModernDVFMCore *core, unsigned window,
    uint64_t offset, unsigned size, uint64_t value);
/* True once the 8-byte word containing offset has been read or written since
 * reset; false for an invalid window or offset. */
bool apple_modern_cpu_dvfm_core_touched(const AppleModernDVFMCore *core,
    unsigned window, uint64_t offset);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_CPU_DVFM "apple-modern-cpu-dvfm"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernDVFMState, APPLE_MODERN_CPU_DVFM)
DeviceState *apple_modern_cpu_dvfm_new(void);
#endif
#endif
