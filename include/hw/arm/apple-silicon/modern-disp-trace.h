/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_DISP_TRACE_H
#define HW_ARM_APPLE_MODERN_DISP_TRACE_H
#include "hw/arm/apple-silicon/modern-board-regions.h"
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/*
 * disp0 bind probe (w7-disp0, milestone M7 step P0).  Two declared, default-off
 * halves driven by one board option, "disp0-probe":
 *
 *  1. ADT property overrides that put back the "compatible" strings the served
 *     Darwin-derived tree strips, so that AppleCLCD2 can match on the
 *     AppleARMIODevice nub the platform driver publishes for /arm-io/disp0.
 *     ATTESTED: the only personality in the pinned iPhone17,3 iOS 27.0 (24A437)
 *     BootKC (sha256 a36b9241...) that can publish an IOMobileFramebuffer is
 *     "AppleADBE0-8970X" of com.apple.driver.AppleMobileDispH17P-DCP, class
 *     AppleCLCD2, IOProviderClass AppleARMIODevice,
 *     IONameMatch ("disp0,t8140", "dispext0,t8140"), with no IOResourceMatch,
 *     IOProbeScore or IOMatchCategory key.  Every string written back is the
 *     byte-exact value of the matching property in the stock tree
 *     (runtime/darwin-reference-27/dtree.stock), which the served tree drops:
 *     only 4 of its 451 nodes keep a "compatible" at all.
 *     DECLARED: the value 1 for "no-dcp-driver", a property the stock tree does
 *     NOT carry and whose consumer is a 4-byte accessor inside the same kext.
 *     Nothing is removed from the tree and no distribution image is written.
 *
 *  2. Logging apertures over the /arm-io/disp0 and /arm-io/dcp0-expert register
 *     windows, so an AP access to them is RECORDED instead of raising an
 *     external abort.  Reads answer zero, writes are discarded, every width and
 *     alignment is accepted - this is an observation instrument, not a hardware
 *     model: no register has any meaning or side effect here.
 *
 * Window provenance (attested, stock tree): /arm-io/disp0 reg has 6 entries and
 * /arm-io/dcp0-expert reg has 17, bus-relative; /arm-io "ranges" maps child 0
 * to parent 0x210000000 for 0x2f0000000 bytes.  A candidate window that lands
 * in DRAM, inside another modelled device, or inside an already accepted
 * window is SKIPPED with its reason kept in the plan rather than silently
 * mapped or merged; dcp0-expert reg[2] is inside disp0 reg[3] in the stock
 * tree, so a skip is the normal case and not an error.
 */

#define APPLE_MODERN_DISP_TRACE_MAX_WINDOWS 32
#define APPLE_MODERN_DISP_TRACE_RECORDS 512

/* Candidate window status. */
enum {
    APPLE_MODERN_DISP_TRACE_MAPPED = 0,
    APPLE_MODERN_DISP_TRACE_SKIP_DRAM,
    APPLE_MODERN_DISP_TRACE_SKIP_DEVICE,
    APPLE_MODERN_DISP_TRACE_SKIP_CONTAINED,
    APPLE_MODERN_DISP_TRACE_SKIP_OVERLAP,
};

/* Candidate node. */
enum {
    APPLE_MODERN_DISP_TRACE_NODE_DISP0 = 0,
    APPLE_MODERN_DISP_TRACE_NODE_DCP_EXPERT,
    APPLE_MODERN_DISP_TRACE_NODE_DCP,
    APPLE_MODERN_DISP_TRACE_NODE_DART_DCP,
    APPLE_MODERN_DISP_TRACE_NODE_DART_DISP0,
    APPLE_MODERN_DISP_TRACE_NODES,
};

typedef struct AppleModernDispTraceWindow {
    uint64_t physical_address;
    uint64_t size;
    uint8_t node;       /* APPLE_MODERN_DISP_TRACE_NODE_* */
    uint8_t reg_index;  /* index inside that node's reg property */
    uint8_t status;     /* APPLE_MODERN_DISP_TRACE_MAPPED or a SKIP_* reason */
} AppleModernDispTraceWindow;

typedef struct AppleModernDispTracePlan {
    AppleModernDispTraceWindow windows[APPLE_MODERN_DISP_TRACE_MAX_WINDOWS];
    unsigned count;   /* candidates considered */
    unsigned mapped;  /* candidates with status MAPPED, in candidate order */
} AppleModernDispTracePlan;

typedef struct AppleModernDispTraceRecord {
    uint64_t offset;
    uint8_t window;  /* index into the plan's mapped-window order */
    uint8_t size;
    uint8_t write;
} AppleModernDispTraceRecord;

typedef struct AppleModernDispTraceCore {
    AppleModernDispTraceRecord records[APPLE_MODERN_DISP_TRACE_RECORDS];
    uint64_t window_reads[APPLE_MODERN_DISP_TRACE_MAX_WINDOWS];
    uint64_t window_writes[APPLE_MODERN_DISP_TRACE_MAX_WINDOWS];
    uint64_t reads, writes, dropped;
    unsigned record_count;
    /* One-based index of the first window ever touched; zero when untouched. */
    unsigned first_window;
} AppleModernDispTraceCore;

/* Profile table for the ADT overrides.  Returns NULL for an unknown name. */
#define APPLE_MODERN_DISP_PROBE_DISP0 "disp0"
#define APPLE_MODERN_DISP_PROBE_NO_DCP "disp0-nodcp"
#define APPLE_MODERN_DISP_PROBE_DCP_CHAIN "dcp-chain"
/* Positive control: restores two unrelated zero-register nodes' compatible so
 * that a driver which certainly matches is observable through the same path. */
#define APPLE_MODERN_DISP_PROBE_CONTROL "override-control"
/* Paired differential: one power-gated and one ungated node, neither a display
 * node, restored in the same boot. */
#define APPLE_MODERN_DISP_PROBE_GATE_CONTROL "gate-control"
#define APPLE_MODERN_DISP_PROBE_NAMES \
    APPLE_MODERN_DISP_PROBE_DISP0 ", " APPLE_MODERN_DISP_PROBE_NO_DCP ", " \
    APPLE_MODERN_DISP_PROBE_DCP_CHAIN ", " APPLE_MODERN_DISP_PROBE_CONTROL ", " \
    APPLE_MODERN_DISP_PROBE_GATE_CONTROL
const AppleModernAdtOverride *apple_modern_disp_probe_profile(const char *name,
                                                              size_t *count);
/* True when the named profile restores a dart,t8110 compatible and therefore
 * also serves its own declared "dart-id" (SPTM panics "error -1 getting
 * dart-id" without one); such a profile cannot be combined with the loader's
 * adt-dart-ids generator, which keys on the INPUT tree and finds no DART at
 * all in the served Darwin-derived tree. */
bool apple_modern_disp_probe_supplies_dart_id(const char *name);

bool apple_modern_disp_trace_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDispTracePlan *output, Error **errp);
const char *apple_modern_disp_trace_node_name(unsigned node);
void apple_modern_disp_trace_core_reset(AppleModernDispTraceCore *core);
/* Never fails: a logging aperture must not fault.  Reads yield zero. */
void apple_modern_disp_trace_core_read(AppleModernDispTraceCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t *value);
void apple_modern_disp_trace_core_write(AppleModernDispTraceCore *core,
    unsigned window, uint64_t offset, unsigned size);
/* True when (window, offset, write) is already in the bounded record list. */
bool apple_modern_disp_trace_core_recorded(const AppleModernDispTraceCore *core,
    unsigned window, uint64_t offset, bool write);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_DISP_TRACE "apple-modern-disp-trace"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernDispTraceState, APPLE_MODERN_DISP_TRACE)
DeviceState *apple_modern_disp_trace_new(const AppleModernDispTracePlan *plan);
#endif
#endif
