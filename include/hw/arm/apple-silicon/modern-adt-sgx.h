/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_ADT_SGX_H
#define HW_ARM_APPLE_MODERN_ADT_SGX_H
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/*
 * /arm-io/sgx -- the GPU node AGXAcceleratorG17P matches on, served back into a
 * Darwin-derived tree that deletes it.
 *
 * WHY THIS NODE AND NOT /arm-io/gfx-asc.  com.apple.AGXG17P has exactly two
 * personalities and the accelerator one is
 *   IOClass         AGXAcceleratorG17P
 *   IOProviderClass AppleARMIODevice
 *   IOMatchCategory IOAcceleratorES
 *   IONameMatch     gpu,t8140 | gpu,t8015 | gpu,t8027 | gpu,t8030 |
 *                   gpu,t8103 | gpu,t8122
 * (read out of the kernelcache's prelink-info.plist; no personality in any of
 * its 323 kexts publishes an accelerator class on a gfx-asc node).  The only
 * node in the stock iPhone17,3 tree carrying "gpu,t8140" is /arm-io/sgx, and
 * /arm-io/gfx-asc is a different chain: iop,ascwrap-v6 -> iop-nub,rtbuddy-v2
 * -> RTBuddyService{role=GFX} -> AGXFirmwareKextG16RTBuddy, which feeds
 * firmware to an accelerator but publishes none.  So the gfx-asc mailbox this
 * board already models (gfx-asc=on) cannot by itself produce the
 * "AGXAccelerator" service iOS 27's Metal-only CoreAnimation looks up:
 * measured, a full 431 s boot with gfx-asc=on issued ZERO MMIO accesses
 * anywhere in that mailbox window, because nothing matched.
 *
 * WHAT IS ATTESTED: every byte of the node, including its "reg", "interrupts",
 * "AAPL,phandle" and "interrupt-parent", is copied by
 * evidence/features-20261017/sgx-adt-node/gen_sgx.py out of the pinned stock
 * tree runtime/darwin-reference-27/dtree.stock (sha256
 * 0a29c3adc1b8621150445e7082630ac221b76a7a168cbff8a3e1f0d5c72992d0), where the
 * node exists exactly once with 26 properties and no children.  Nothing is
 * renumbered: measured, the served tree keeps the stock numbering (AIC still
 * 0x20, mapper-gfx-asc still 0x110, highest phandle 0x1c4 in both trees) and
 * simply drops nodes, so the stock sgx phandle 0x10b is unused in the served
 * tree and "interrupt-parent" = 0x20 still resolves to /arm-io/aic.  Likewise
 * "function-mcc_dataset" still names an existing node (phandle 0x28 =
 * /arm-io/mcc).
 *
 * MEASURED CONSEQUENCE, AND WHY THIS IS STILL DEFAULT OFF.  Serving the node
 * alone does NOT reach the accelerator: it stops the boot in SPTM, before the
 * console.  Measured (evidence/features-20261017/v66-sgx-node, 431.1 s): zero
 * serial bytes and zero MMIO accesses of any kind, against 18,049 serial bytes
 * and 2.17 MB of MMIO trace in the byte-identical v65 run whose only difference
 * is this option.  SPTM owns the GPU's address translator and keys it on this
 * exact node (sptm __TEXT_EXEC, iPhone17,3 boot components):
 *   uat_is_enabled()         0xfffffff0270b0b28
 *     lookup("/arm-io/sgx")  0xfffffff0270b0b5c -- ABSENT (-1) returns false,
 *                            which is why every earlier boot was unaffected;
 *     lookup("/chosen") then getprop("gpu-iouat") 0xfffffff0270b0bac --
 *                            ABSENT returns TRUE (fail-open), length must be 4,
 *                            and only an explicit ZERO returns false.
 *   uat_bootstrap_parse_dt() ~0xfffffff0270af8b0, then requires, in order,
 *     "agx-address-space-mgmt-mode" (4 bytes, nonzero -- the stock node has it,
 *     = 1) and then "gfx-shared-region-base" (8 bytes), which the stock node
 *     does NOT carry: 0xfffffff0270afa2c branches to 0xfffffff0270b0abc, which
 *     calls the non-returning panic at 0xfffffff0270f7770 with "%s: error %d
 *     looking up %s" / "uat_get_dt_prop".  It goes on to demand
 *     gfx-shared-region-size (>= SPTM_PAGE_SIZE and a multiple of it),
 *     gfx-shared-l2-region-base/size (exactly one page), gpu-region-base/size
 *     and gfx-handoff-base/size -- every one of them an iBoot hand-off value
 *     that the stock pre-iBoot node lacks.
 * So this option is, as measured, a boot-stopper on its own.  Two ways out, in
 * cost order: (1) serve /chosen "gpu-iouat" = u32 0, which makes
 * uat_is_enabled() return false so SPTM skips the GPU translator entirely while
 * the node stays visible to IOKit -- /chosen is loader-owned, so that needs its
 * own metadata input flag, not an override; or (2) build the real carveout
 * hand-off (a DRAM-tail region plus those eight properties) to SPTM's measured
 * size predicates.  Neither is done here.
 *
 * WHAT IS NOT CLAIMED: that the accelerator starts, or even probes.  Nothing in
 * this board has yet observed AGXAcceleratorG17P matching.  The node makes the
 * match possible once SPTM is satisfied; start() may still refuse without a
 * booted GFX firmware, in which case the service is detached and
 * IOServiceGetMatchingService("AGXAccelerator") keeps returning zero.  The
 * stock node is also the pre-iBoot form: 26 properties, not the 51 a real
 * device shows, with "perf-states" 128 zero bytes and "perf-state-count" 0, so
 * anything DVFM needs is absent by construction.  Opt-in, default off.
 */
const AppleModernAdtNode *apple_modern_adt_sgx_node(void);

#endif
