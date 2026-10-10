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
 * /arm-io/dcp an actual AppleRTKit peer, with the intended management HELLO / endpoint-roll-call exchange.
 * Modern RTBuddy has not yet completed it; APPLE_MODERN_DCP_IOP_NUB_NAME
 * below is the predicted nub name, not a measured runtime service.
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
 * DECLARED ENDPOINT NUMBER (modern DCP naming remains unmeasured): in-tree
 * RTKit reserves raw endpoints 0..31 and register_user_ep() takes a relative
 * index. Legacy SMC registers relative 0/raw32, with an SMCEndpoint1
 * personality. Public Asahi, by analogy to another generation, uses raw0x37
 * for IOMFB; applying the inferred raw-minus31 bias predicts DCPEndpoint24.
 * The modern personality's name24 is attested, but this does not establish
 * modern DCP's raw number. This model advertises relative23/raw55 as a
 * declared hypothesis, logs the predicted name, and implements no user ABI.
 *
 * DECLARED modes:
 *   - "v6" / "v4": a guest-started RTKit peer with preloaded/running flags.
 *     Register layout remains a declared choice; the ascwrap-v6 compatible
 *     string alone does not determine the emulator's layout enum.
 *   - "v6-quiesced": guest-started V6 peer without those two flags.
 *   - "flags-only": those two flags without a peer.
 *   - "v6-prestarted": reset establishes RUN and queues the model HELLO,
 *     with the two flags. No firmware is executed.
 *   - "v6-prestarted-quiesced": the same reset-started peer without flags.
 *
 *   - "v6-expert-start": no flags/reset prestart; additionally owns the ADT
 *     expert control register. Its measured on-write starts this peer later.
 *     This bridge and register readback are declared; no firmware executes.
 *
 * Owned AP polling ROMs qualify HELLO/epmap/power exchanges through resets.
 * Measured modern guest flagged v6 and v6-prestarted arms both fail the
 * firmware-load REQUIRE before any handled DCP wrapper/mailbox accesses.
 * The no-flags prestarted arm reaches its service-plane dump without that
 * REQUIRE failure, still with no guest MMIO or endpoint/link/framebuffer.
 * Reset start is thus not independently sufficient for modern bootstrap.
 * See features-20261009/w14-endpoint for exact pins, traces and limitations.
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
/* Declared raw IOMFB candidate; modern DCP mapping has not been measured. */
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
    APPLE_MODERN_DCP_IOP_MODE_V6_EXPERT_START,
};
#define APPLE_MODERN_DCP_IOP_NAME_V6 "v6"
#define APPLE_MODERN_DCP_IOP_NAME_V4 "v4"
#define APPLE_MODERN_DCP_IOP_NAME_V6_QUIESCED "v6-quiesced"
#define APPLE_MODERN_DCP_IOP_NAME_FLAGS "flags-only"
#define APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED "v6-prestarted"
#define APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED_QUIESCED "v6-prestarted-quiesced"
#define APPLE_MODERN_DCP_IOP_NAME_V6_EXPERT_START "v6-expert-start"
#define APPLE_MODERN_DCP_IOP_MODE_NAMES \
    APPLE_MODERN_DCP_IOP_NAME_V6 ", " APPLE_MODERN_DCP_IOP_NAME_V4 ", " \
    APPLE_MODERN_DCP_IOP_NAME_V6_QUIESCED ", " APPLE_MODERN_DCP_IOP_NAME_FLAGS ", " \
    APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED ", " \
    APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED_QUIESCED ", " \
    APPLE_MODERN_DCP_IOP_NAME_V6_EXPERT_START

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
    /* Optional expert control, validated from ADT only for v6-expert-start.
     * On/off readback and control-to-peer start are declared behavior. */
    uint64_t expert_control_address;
    uint32_t expert_control_on;
    uint32_t expert_control_off;
    uint32_t interrupts[APPLE_MODERN_DCP_IOP_IRQS];
    /* ADT "role" of /arm-io/dcp, NUL-terminated; the %s of "%sEndpoint%u". */
    char role[APPLE_MODERN_DCP_IOP_ROLE_MAX];
    /* Raw RTKit endpoint published, and the user-endpoint index for it. */
    unsigned endpoint_raw;
    unsigned endpoint_user;
    /* Declared predicted nub name; not evidence of a published guest service. */
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
