/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_CPU_DVFM_H
#define HW_ARM_APPLE_MODERN_CPU_DVFM_H
#include "hw/arm/apple-silicon/modern-board-regions.h"

/*
 * Per-cluster CPU DVFM state tables as ApplePMGR reads them (pinned BootKC
 * a36b9241): AppleT8140PMGR's reader at 0xfffffff009848900 forms the offset
 * 0xe78008 + state * 0x40 from the arm-io base, loads 64 bits and returns bits
 * [42:38]; sibling readers use other fields. The E cluster table starts at
 * 0x210e78000 and the P cluster table at 0x211e78000 (the cluster stride is
 * 0x1000000, as for cpu-impl-reg 0x210050000 / 0x211050000). The driver stores
 * the values as registry properties; it does not program the registers.
 *
 * DECLARED, not attested: each window is a plain storage page that resets to
 * zero. The real contents are per-chip DVFM entries written by firmware
 * (frequency and voltage-ID fields); none is available for this device, so
 * this is a boot-progress diagnostic profile, not calibration or silicon
 * behaviour. 8-byte and 4-byte accesses are accepted; anything else faults.
 */
#define APPLE_MODERN_DVFM_WINDOWS 2
#define APPLE_MODERN_DVFM_SPAN 0x1000

typedef struct AppleModernDVFMPlan {
    uint64_t addresses[APPLE_MODERN_DVFM_WINDOWS];
} AppleModernDVFMPlan;
typedef struct AppleModernDVFMCore {
    uint64_t words[APPLE_MODERN_DVFM_WINDOWS][APPLE_MODERN_DVFM_SPAN / 8];
    uint64_t reads, writes;
} AppleModernDVFMCore;

/* Windows lie in the arm-io range at E 0x210e78000 and P 0x211e78000 (matched
 * against /arm-io ranges and the T8140 cpu node geometry). */
bool apple_modern_cpu_dvfm_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDVFMPlan *output, Error **errp);
void apple_modern_cpu_dvfm_core_reset(AppleModernDVFMCore *core);
bool apple_modern_cpu_dvfm_core_read(AppleModernDVFMCore *core, unsigned window,
    uint64_t offset, unsigned size, uint64_t *value);
bool apple_modern_cpu_dvfm_core_write(AppleModernDVFMCore *core, unsigned window,
    uint64_t offset, unsigned size, uint64_t value);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_CPU_DVFM "apple-modern-cpu-dvfm"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernDVFMState, APPLE_MODERN_CPU_DVFM)
DeviceState *apple_modern_cpu_dvfm_new(void);
#endif
#endif
