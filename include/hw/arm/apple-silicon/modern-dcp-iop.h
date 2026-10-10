/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_DCP_IOP_H
#define HW_ARM_APPLE_MODERN_DCP_IOP_H
#include "hw/arm/apple-silicon/modern-board-regions.h"
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/*
 * Declared, default-off RTKit coprocessor stand-in for /arm-io/dcp
 * (w13-endpoint, ledger W-12 continuation).  Where modern-dcp-asc.h is an
 * OBSERVATION model with an empty mailbox and no peer, this one gives
 * /arm-io/dcp an actual AppleRTKit peer, so that RTBuddy's management endpoint
 * can complete its HELLO / endpoint-roll-call handshake and publish the
 * RTBuddyEndpointService nub named in APPLE_MODERN_DCP_IOP_NUB_NAME below.
 * The transport, the mailbox register file and the management protocol are NOT
 * written here: they are the in-tree hw/misc/apple-silicon/a7iop RTKit that
 * this board's own legacy A13 SMC and AOP devices already use.  This module is
 * only the plan (which window, which interrupt lines, which endpoint number)
 * plus the refusals.
 *
 * ATTESTED (stock ADT runtime/darwin-reference-27/dtree.stock, sha256
 * 0a29c3ad...; the served tree keeps all of this except "compatible"):
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
 *   - RTBuddyManagementEndpoint has _handleHello, _handlePowerAck and
 *     _handleEPRollCall, gated on kRtbIopStatusWaitingForVersion ->
 *     kRtbIopStatusVersionOk, i.e. the endpoint list comes from a roll call
 *     over the mailbox and from nowhere else.
 *   - the endpoint personality numbering is 1-based over 32 slots:
 *     com.apple.driver.AppleSPU names AOPEndpoint1 .. AOPEndpoint32 and
 *     com.apple.driver.AppleAOP2 names AOP2Endpoint1 .. AOP2Endpoint24.
 *
 * MEASURED / in-tree precedent: hw/misc/apple-silicon/a7iop/rtkit.c reserves
 * raw endpoints 0..31 for RTKit control use (EP_USER_START = 32) and offsets
 * every "user" endpoint by 32; the legacy A13 board registers SMC user
 * endpoint 0 and Apple's matching personality for it is "SMCEndpoint1".  So the
 * name index is raw - 31, and 32 user slots is exactly the AOPEndpoint1..32
 * list above.
 *
 * DECLARED-INFERRED, and this is the one number the whole module turns on:
 *   raw endpoint 0x37 is the IOMFB channel, so index 0x37 - 31 = 24 and the nub
 *   is named "DCPEndpoint24", the name AppleDCPLinkServiceSoC matches.  0x37
 *   comes from the retained public Asahi table
 *   modern-emulator/inventory/sources/display-gpu/linux-asahi-drm-apple-dcp-internal.h
 *   (IOMFB_ENDPOINT 0x37) -- ANALOGY, another SoC generation -- and lands on
 *   Apple's distinguished index 24 under the attested arithmetic above.  If it
 *   is wrong, the nub appears under a different name and no
 *   AppleDCPLinkServiceSoC matches; that is a visible, falsifiable outcome, not
 *   a silent one, which is why the nub name is reported at startup.
 *
 * DECLARED, the two modes:
 *   - "ap-start": the RTKit peer stays silent until the guest writes CPU_CTRL
 *     RUN on the wrapper block, which is the in-tree legacy behaviour and
 *     changes nothing on its own if the guest never writes it.
 *   - "iboot-running": the peer announces itself (RTKit HELLO) as soon as the
 *     machine is created.  This is a CLAIM, and a false one about our loader:
 *     /arm-io/dcp/iop-dcp-nub says "quiesced" and AppleASCWrapV6 expects "ASC
 *     firmware must be loaded by iBoot", i.e. on real hardware the DCP is
 *     already running its iBoot-loaded firmware before XNU starts and its
 *     HELLO is already in the mailbox.  THIS LOADER PLACES NO DCP FIRMWARE and
 *     publishes no /chosen/carveout-memory-map carveout, so the handshake is
 *     answered by this model, not by Apple's DCP firmware.  Nothing behind the
 *     endpoint is implemented: the endpoint accepts messages and replies to
 *     none.
 */

/* Attested wrapper-window size; a tree that disagrees is refused. */
#define APPLE_MODERN_DCP_IOP_WRAPPER_SIZE UINT64_C(0x88000)
/* Four lines, matching AppleA7IOP's four mailbox interrupts. */
#define APPLE_MODERN_DCP_IOP_IRQS 4
/* RTKit reserves raw endpoints below this for its own control channels. */
#define APPLE_MODERN_DCP_IOP_EP_USER_START 32u
/* name index = raw - bias; see the attested derivation above. */
#define APPLE_MODERN_DCP_IOP_EP_NAME_BIAS 31u
/* The IOMFB channel (declared-inferred; public Asahi IOMFB_ENDPOINT). */
#define APPLE_MODERN_DCP_IOP_EP_IOMFB 0x37u
/* What AppleDCPLinkServiceSoC's IONameMatch expects to see. */
#define APPLE_MODERN_DCP_IOP_NUB_NAME "DCPEndpoint24"
#define APPLE_MODERN_DCP_IOP_ROLE_MAX 16

enum {
    APPLE_MODERN_DCP_IOP_AP_START = 0,
    APPLE_MODERN_DCP_IOP_IBOOT_RUNNING = 1,
};
#define APPLE_MODERN_DCP_IOP_MODE_AP_START "ap-start"
#define APPLE_MODERN_DCP_IOP_MODE_IBOOT "iboot-running"
#define APPLE_MODERN_DCP_IOP_MODE_NAMES \
    APPLE_MODERN_DCP_IOP_MODE_AP_START ", " APPLE_MODERN_DCP_IOP_MODE_IBOOT
/* Returns false for an unknown name. */
bool apple_modern_dcp_iop_mode(const char *name, unsigned *mode);

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

#endif
