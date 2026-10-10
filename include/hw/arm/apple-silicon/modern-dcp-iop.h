/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_DCP_IOP_H
#define HW_ARM_APPLE_MODERN_DCP_IOP_H
#include "hw/arm/apple-silicon/modern-board-regions.h"
#include "hw/arm/apple-silicon/modern-boot-metadata.h"
#include "hw/arm/apple-silicon/modern-disp-trace.h" /* AppleModernAdtOverride */

/*
 * Declared, default-off RTKit coprocessor stand-in for /arm-io/dcp
 * (w14-endpoint, ledger W-12 continuation).  Where modern-dcp-asc.h is an
 * OBSERVATION model with an empty mailbox and no peer, this one gives
 * /arm-io/dcp an actual AppleRTKit peer, so that RTBuddy's management endpoint
 * can complete its HELLO / endpoint-roll-call handshake and publish the
 * RTBuddyEndpointService nub named in APPLE_MODERN_DCP_IOP_NUB_NAME below.
 * The transport, the mailbox register file and the management protocol are NOT
 * written here: they are the in-tree hw/misc/apple-silicon/a7iop RTKit that
 * this board's own legacy A13 SMC, AOP, ANS, SIO and baseband devices already
 * use.  This module is the plan (which window, which interrupt lines, which
 * endpoint number), the two ADT flags, the device wrapper, and the refusals.
 *
 * ATTESTED (stock ADT runtime/darwin-reference-27/dtree.stock; the served tree
 * keeps all of this except "compatible"):
 *   /arm-io/dcp  compatible "iop,ascwrap-v6", role "DCP",
 *                reg[0] bus 0x202e00000 size 0x88000  (the AKF wrapper block),
 *                interrupts = 0x2a8, 0x2a7, 0x2aa, 0x2a9  (four lines),
 *                iommu-parent, idle-ctrl-check, no "cpu-ctrl-filtered".
 *   /arm-io/dcp/iop-dcp-nub  compatible "iop-nub,rtbuddy-v2", and it carries
 *                "quiesced", "user-power-managed" = 1, "no-firmware-service",
 *                "watchdog-enable", "cold-boot-after-hibernate" and "routes".
 *                It carries NEITHER "pre-loaded" NOR "running".
 *
 * ATTESTED (pinned BootKC a36b9241..., __PRELINK_INFO,__info and __cstring
 * runs; no shipped function body was disassembled):
 *   - com.apple.driver.AppleMobileDispH17P-DCP publishes AppleDCPLinkServiceSoC
 *     with IOProviderClass "RTBuddyEndpointService" and
 *     IONameMatch ["DCPEndpoint24", "DCPEXTEndpoint24"].
 *   - the RTBuddy endpoint nub-name format string is "%sEndpoint%u"
 *     (BootKC 0xb51aff, inside the RTBuddyEndpointService string run).
 *   - com.apple.driver.AppleDCP's DCPEndpointV2 personality names
 *     DCPEndpoint1 .. DCPEndpoint24 and nothing above 24; AppleSPU names
 *     AOPEndpoint1 .. AOPEndpoint32; AppleAOP2 names AOP2Endpoint1 ..
 *     AOP2Endpoint24; AppleSMC names exactly SMCEndpoint1; AppleSmartIO2 names
 *     exactly SIOEndpoint1.  So Apple's name index is 1-based.
 *
 * THE ENDPOINT NUMBER, derived three independent ways that agree.  In-tree
 * RTKit reserves raw endpoints 0..31 (EP_USER_START = 32, a7iop/rtkit.c:28)
 * and apple_rtkit_register_user_ep() takes a USER-RELATIVE index, adding the
 * offset itself.  (1) in-tree precedent: smc.c registers user-relative
 * kSMCKeyEndpoint = 0, i.e. raw 32, and Apple's only SMC endpoint personality
 * is SMCEndpoint1 -- so name index = raw - 31 = user-relative + 1.
 * (2) public Asahi (ANALOGY, another SoC generation): dcp-internal.h gives
 * SYSTEM_ENDPOINT = 0x20 and IOMFB_ENDPOINT = 0x37; under name = raw - 31 that
 * maps SYSTEM -> 1 and IOMFB -> 24.  (3) the attested DCPEndpoint list stops
 * at exactly 24, the index AppleDCPLinkServiceSoC claims.  Therefore:
 *   name index 24  <->  raw 0x37 (55)  <->  user-relative 23.
 * This module passes the USER-RELATIVE index to the existing RTKit layer and
 * never hand-computes a raw number; the raw value and the nub name it implies
 * are reported at startup so a wrong index is visible, not silent.
 *
 * DECLARED, the four modes:
 *   - "v6" / "v4": instantiate the RTKit peer with that register file and set
 *     the two ADT flags below.  Which register file /arm-io/dcp's driver wants
 *     is NOT decidable from the ADT string: sep.c:4153 passes APPLE_A7IOP_V4
 *     for a node whose compatible is "iop,ascwrap-v6", and a7iop/base.h says
 *     why ("this enum tracks our register files, not Apple's").  Both are
 *     offered so the question is settled by measurement.
 *   - "v6-quiesced": the V6 peer WITHOUT the two ADT flags, so the flags can
 *     be attributed separately from the peer.
 *   - "flags-only": the two ADT flags and NO peer at all, so the flags can be
 *     measured against the dcp-asc observation apertures.
 *
 * DECLARED, the two ADT flags ("pre-loaded" = 1 and "running" = 1 on
 * /arm-io/dcp/iop-dcp-nub).  They are NOT in the stock tree.  All five in-tree
 * RTKit devices set exactly this pair on their own nub (smc.c:535, aop.c:876,
 * ans.c:256, apple_sio.c:856, and baseband through smc), which is this tree's
 * unanimous precedent for "iBoot already loaded and started this IOP".  For
 * /arm-io/dcp that claim is FALSE about our loader: it places no DCP firmware
 * and publishes no /chosen/carveout-memory-map region-id-N or segment-ranges.
 * The handshake is answered by this model, not by Apple's DCP firmware, and
 * nothing behind the endpoint is implemented: the endpoint counts the messages
 * it receives and replies to none.
 */

/* Attested wrapper-window size; a tree that disagrees is refused. */
#define APPLE_MODERN_DCP_IOP_WRAPPER_SIZE UINT64_C(0x88000)
/* Four lines, matching AppleA7IOP's four mailbox interrupts. */
#define APPLE_MODERN_DCP_IOP_IRQS 4
/* RTKit reserves raw endpoints below this for its own control channels. */
#define APPLE_MODERN_DCP_IOP_EP_USER_START 32u
/* Declared inferred name bias from legacy precedent; not modern measured. */
#define APPLE_MODERN_DCP_IOP_EP_NAME_BIAS 31u
/* The IOMFB channel's Apple name index, attested from AppleDCPLinkServiceSoC. */
#define APPLE_MODERN_DCP_IOP_EP_NAME_INDEX 24u
/* The IOMFB channel's raw endpoint (= name index + bias; public Asahi agrees). */
#define APPLE_MODERN_DCP_IOP_EP_IOMFB \
    (APPLE_MODERN_DCP_IOP_EP_NAME_INDEX + APPLE_MODERN_DCP_IOP_EP_NAME_BIAS)
/* What AppleDCPLinkServiceSoC's IONameMatch expects to see. */
#define APPLE_MODERN_DCP_IOP_NUB_NAME "DCPEndpoint24"
#define APPLE_MODERN_DCP_IOP_ROLE_MAX 16

enum {
    APPLE_MODERN_DCP_IOP_MODE_V6 = 0,
    APPLE_MODERN_DCP_IOP_MODE_V4,
    APPLE_MODERN_DCP_IOP_MODE_V6_QUIESCED,
    APPLE_MODERN_DCP_IOP_MODE_FLAGS_ONLY,
    APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED,
    APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED_QUIESCED,
};
#define APPLE_MODERN_DCP_IOP_NAME_V6 "v6"
#define APPLE_MODERN_DCP_IOP_NAME_V4 "v4"
#define APPLE_MODERN_DCP_IOP_NAME_V6_QUIESCED "v6-quiesced"
#define APPLE_MODERN_DCP_IOP_NAME_FLAGS "flags-only"
#define APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED "v6-prestarted"
#define APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED_QUIESCED "v6-prestarted-quiesced"
#define APPLE_MODERN_DCP_IOP_MODE_NAMES \
    APPLE_MODERN_DCP_IOP_NAME_V6 ", " APPLE_MODERN_DCP_IOP_NAME_V4 ", " \
    APPLE_MODERN_DCP_IOP_NAME_V6_QUIESCED ", " APPLE_MODERN_DCP_IOP_NAME_FLAGS ", " \
    APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED ", " \
    APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED_QUIESCED

/* Returns false for an unknown name. */
bool apple_modern_dcp_iop_mode(const char *name, unsigned *mode);
/* True when this mode instantiates a peer device (i.e. not flags-only). */
bool apple_modern_dcp_iop_mode_has_peer(unsigned mode);
/* True when this mode serves the two declared ADT flags. */
bool apple_modern_dcp_iop_mode_has_flags(unsigned mode);
/*
 * The two declared ADT overrides ("pre-loaded", "running" on
 * /arm-io/dcp/iop-dcp-nub).  The returned pointers are static storage.
 */
const AppleModernAdtOverride *apple_modern_dcp_iop_overrides(size_t *count);

typedef struct AppleModernDcpIopPlan {
    uint64_t wrapper_address;
    uint64_t wrapper_size;
    uint32_t interrupts[APPLE_MODERN_DCP_IOP_IRQS];
    /* ADT "role" of /arm-io/dcp, NUL-terminated; the %s of "%sEndpoint%u". */
    char role[APPLE_MODERN_DCP_IOP_ROLE_MAX];
    /* Raw RTKit endpoint published, and the user-endpoint index for it. */
    unsigned endpoint_raw;
    unsigned endpoint_user;
    /* The nub name the guest is expected to create for it. */
    char nub_name[APPLE_MODERN_DCP_IOP_ROLE_MAX + 16];
} AppleModernDcpIopPlan;

/*
 * Derive "<role>Endpoint<index>" for a raw RTKit endpoint.  Refuses a raw
 * endpoint below EP_USER_START (those are RTKit's own control channels and get
 * no nub), a raw endpoint that would exceed one byte, an empty or overlong
 * role, and a role carrying anything but printable ASCII.
 */
bool apple_modern_dcp_iop_endpoint_name(const char *role, unsigned raw,
                                        char *out, size_t out_size,
                                        unsigned *index, Error **errp);

bool apple_modern_dcp_iop_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    unsigned endpoint_raw, AppleModernDcpIopPlan *output, Error **errp);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_DCP_IOP "apple-modern-dcp-iop"
OBJECT_DECLARE_TYPE(AppleModernDcpIop, AppleModernDcpIopClass,
                    APPLE_MODERN_DCP_IOP)
/*
 * Creates the RTKit peer: MMIO region 0 is the wrapper block (the two mailbox
 * sub-regions sit inside it, placed by the existing a7iop code) and the four
 * sysbus IRQ lines are the AP mailbox's, passed through positionally, in the
 * ADT "interrupts" order -- the same positional convention t8030 uses for SMC,
 * SIO and ANS.  mode must have a peer (see apple_modern_dcp_iop_mode_has_peer).
 */
DeviceState *apple_modern_dcp_iop_new(const AppleModernDcpIopPlan *plan,
                                      unsigned mode);
/* Observability: messages received on the published user endpoint. */
uint64_t apple_modern_dcp_iop_messages(DeviceState *dev);
/* Observability: true once the RTKit roll-call completed (boot_done fired). */
bool apple_modern_dcp_iop_rollcall_done(DeviceState *dev);
#endif

#endif
