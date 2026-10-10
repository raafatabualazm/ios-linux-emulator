/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_DCP_ASC_H
#define HW_ARM_APPLE_MODERN_DCP_ASC_H
#include "hw/arm/apple-silicon/modern-board-regions.h"
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/*
 * Declared, default-off ASC v6 wrapper apertures for /arm-io/dcp (w12-dcp,
 * ledger W-12, the W-01 continuation).  This is an OBSERVATION MODEL with three
 * decoded registers, not a coprocessor: it owns the three /arm-io/dcp register
 * windows so that AppleA7IOP/AppleASCWrapV6 accesses are answered and counted
 * instead of raising an external abort, and so that the ONE register whose
 * predicate is attested can be answered either way under board control.
 *
 * ATTESTED (pinned stock ADT runtime/darwin-reference-27/dtree.stock, sha256
 * 0a29c3ad..., and the served tree 0e722366... which keeps reg unchanged):
 * /arm-io/dcp is compatible "iop,ascwrap-v6" with exactly three reg windows,
 *   reg[0] bus 0x202e00000 size 0x88000   (the AKF wrapper block)
 *   reg[1] bus 0x202850000 size 0x4000    (the core block)
 *   reg[2] bus 0x202e2c000 size 0x3c008
 * and it carries "idle-ctrl-check" and no "cpu-ctrl-filtered".  The reg[0]
 * size 0x88000 and the reg[1] size 0x4000 are the SAME on every iop,ascwrap-v6
 * node in this ADT (/arm-io/aop, /arm-io/smc, /arm-io/dcp; /arm-io/sep has the
 * same reg[0] and a larger core), which is what identifies reg[0] as the
 * wrapper and reg[1] as the core.  MEASURED (plan arithmetic over those same
 * bytes): reg[2] lies entirely INSIDE reg[0] at offset +0x2c000, so the node
 * has only TWO disjoint apertures, not three, and /arm-io/aop has the same
 * 0x3c008 sub-window inside its own reg[0].  reg[2] is therefore a named alias
 * and is skipped as contained rather than mapped twice.
 *
 * ATTESTED (pinned BootKC a36b9241..., via this project's earlier AppleA7IOP
 * oracle features-20261007/xnu-a7iop-oracle/ADJUDICATION.md and the
 * coprocessors:17 inventory row): on the wrapper block the driver reads 0x40,
 * 0x44, 0x8000, 0x8110, 0x8114 and 0x8180 + 4k for k < 128; writes 0x44,
 * 0x1004, 0x1014 and 0x8114; stores 128 bits at 0x8800 and loads 128 bits at
 * 0x8830; CPU_CTRL is 0x44 with RUN = bit 4.  On the core block,
 * AppleASCWrapV6's slot +0x6d8 reads 64 bits at offset 0 and panics
 * "ASC firmware must be loaded by iBoot" when bit 0 is clear.
 *
 * DECLARED, and this is the whole substance of the model:
 *  - core offset 0 bit 0 = 1 claims the DCP firmware was pre-loaded by iBoot.
 *    IT WAS NOT.  This loader places no coprocessor firmware and publishes no
 *    /chosen/carveout-memory-map region-id-N or segment-ranges.  The
 *    FIRMWARE_ABSENT mode exists so the claim can be withdrawn in one boot and
 *    Apple's own panic observed as a behaviour oracle.
 *  - wrapper 0x40 bit 0 = 1 ("idle"), because /arm-io/dcp carries
 *    idle-ctrl-check and the only predicate the driver applies is a bit test.
 *  - wrapper 0x8000 (IDLE_STATUS) low two bits = 3 before a RUN write and 0
 *    after, following the in-tree regs-v6.c reading of the same register.
 *  - the mailbox is EMPTY and has NO peer: both CONTROL words report empty, a
 *    128-bit load at 0x8830 yields zeros, and nothing consumes a 0x8800 store.
 *    NO RTKit/RTBuddy endpoint is published and none is claimed.
 *  - every other offset in all three windows answers zero and is recorded.
 *    Reads answering zero is NOT evidence that zero is right.
 */

#define APPLE_MODERN_DCP_ASC_WINDOWS 3
#define APPLE_MODERN_DCP_ASC_RECORDS 256

/* Attested window sizes; a tree that disagrees is refused. */
#define APPLE_MODERN_DCP_ASC_WRAPPER_SIZE UINT64_C(0x88000)
#define APPLE_MODERN_DCP_ASC_CORE_SIZE UINT64_C(0x4000)
#define APPLE_MODERN_DCP_ASC_ALIAS_SIZE UINT64_C(0x3c008)

/* Candidate reg entries. */
#define APPLE_MODERN_DCP_ASC_CANDIDATES 3
/* Mapped apertures, in the order the device creates its memory regions. */
#define APPLE_MODERN_DCP_ASC_MAPPED 2
enum {
    APPLE_MODERN_DCP_ASC_WRAPPER = 0,
    APPLE_MODERN_DCP_ASC_CORE = 1,
};

/* Board modes.  "off" is the absence of the option, not a value here. */
enum {
    APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED = 0,
    APPLE_MODERN_DCP_ASC_FIRMWARE_ABSENT = 1,
};
#define APPLE_MODERN_DCP_ASC_MODE_LOADED "fw-loaded"
#define APPLE_MODERN_DCP_ASC_MODE_ABSENT "fw-absent"
#define APPLE_MODERN_DCP_ASC_MODE_NAMES \
    APPLE_MODERN_DCP_ASC_MODE_LOADED ", " APPLE_MODERN_DCP_ASC_MODE_ABSENT
/* Returns false for an unknown name. */
bool apple_modern_dcp_asc_mode(const char *name, unsigned *mode);

typedef struct AppleModernDcpAscPlan {
    /* Candidate reg entries in ADT order. */
    uint64_t addresses[APPLE_MODERN_DCP_ASC_CANDIDATES];
    uint64_t sizes[APPLE_MODERN_DCP_ASC_CANDIDATES];
    /* True when this candidate lies inside an earlier one and is not mapped. */
    bool contained[APPLE_MODERN_DCP_ASC_CANDIDATES];
    unsigned count;  /* candidates considered */
    unsigned mapped; /* candidates actually mapped, in candidate order */
} AppleModernDcpAscPlan;

typedef struct AppleModernDcpAscRecord {
    uint64_t offset;
    uint8_t window;
    uint8_t size;
    uint8_t write;
    uint8_t modelled; /* 1 when this offset has a decoded meaning above */
} AppleModernDcpAscRecord;

typedef struct AppleModernDcpAscCore {
    AppleModernDcpAscRecord records[APPLE_MODERN_DCP_ASC_RECORDS];
    uint64_t window_reads[APPLE_MODERN_DCP_ASC_WINDOWS];
    uint64_t window_writes[APPLE_MODERN_DCP_ASC_WINDOWS];
    uint64_t reads, writes, dropped;
    uint64_t firmware_bit_reads;  /* 64-bit reads of core offset 0 */
    uint64_t doorbells;           /* writes to wrapper 0x1004 / 0x1014 */
    uint64_t mailbox_sends;       /* stores into the wrapper send frame */
    uint64_t mailbox_recv_polls;  /* loads from the wrapper receive frame */
    uint32_t cpu_ctrl;
    unsigned record_count;
    unsigned mode;
    bool running; /* set by a CPU_CTRL write with RUN; never cleared by reads */
    /* One-based record index of the first access this model does not decode;
     * zero while every access so far had a decoded meaning. */
    unsigned first_unmodelled;
} AppleModernDcpAscCore;

bool apple_modern_dcp_asc_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDcpAscPlan *output, Error **errp);
const char *apple_modern_dcp_asc_window_name(unsigned candidate);
void apple_modern_dcp_asc_core_reset(AppleModernDcpAscCore *core,
                                     unsigned mode);
/* Never fails: an aperture must not fault.  Undecoded offsets answer zero. */
void apple_modern_dcp_asc_core_read(AppleModernDcpAscCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t *value);
void apple_modern_dcp_asc_core_write(AppleModernDcpAscCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t value);
/* True when (window, offset, write) is already in the bounded record list. */
bool apple_modern_dcp_asc_core_recorded(const AppleModernDcpAscCore *core,
    unsigned window, uint64_t offset, bool write);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_DCP_ASC "apple-modern-dcp-asc"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernDcpAscState, APPLE_MODERN_DCP_ASC)
DeviceState *apple_modern_dcp_asc_new(const AppleModernDcpAscPlan *plan,
                                      unsigned mode);
#endif
#endif
