/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_KC_PATCH_H
#define HW_ARM_APPLE_MODERN_KC_PATCH_H

/* For Error (QEMU's or the standalone test adapter). */
#include "hw/arm/apple-silicon/modern-boot-layout.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Declared, opt-in kernel-cache compatibility shim (off by default).
 *
 * The apple-modern board has no ignition/SEP infrastructure, so the
 * AppleImage4 ignition-blob sysctl handler (_darwin_trap_ignition_get_blob)
 * never returns and userspace libignition stalls before launchd. This is the
 * one modification the pinned Darwin-VM reference (qemu-sptm 2867d847,
 * hw/arm/xnu_patch.c patch_img4_deadlock) applies to boot its restore ramdisk.
 *
 * This function performs the same edit, but only on the board's PRIVATE
 * in-memory copy of the boot kernel cache (never the firmware file on disk),
 * and only when the board's img4-ignition-compat property is set. It rewrites
 * the first three instructions of that one handler to return zero. Every
 * offset is recomputed from the image and bounds-checked; on any mismatch the
 * buffer is left untouched and the function returns false with an error.
 *
 * It is a compatibility measure, not Apple hardware fidelity: it changes guest
 * kernel code so unmodified firmware can proceed past a missing dependency.
 * It is inventoried in docs/darwin-port.md and reported at run time.
 */
bool apple_modern_kc_ignition_compat(uint8_t *bootkc, size_t len, Error **errp);

/*
 * Declared, opt-in md ram-disk width compatibility edit (off by default).
 *
 * ROOT CAUSE, from Apple's published source (apple-oss-distributions/xnu,
 * tag xnu-12377.121.6):
 *
 *   bsd/dev/memdev.c:160-169  struct mdev stores the ram disk as
 *       uint64_t mdBase;  (base page number)
 *       uint32_t mdSize;  (size in 4 KiB PAGES)
 *     so the stored size itself has 16 TiB of headroom and is NOT the limit.
 *
 *   iokit/bsddev/IOKitBSDInit.cpp:787-792 reads /chosen/memory-map RAMDisk as
 *     two uintptr_t words, refuses only above ((uint64_t)UINT_MAX << 12), and
 *     calls mdevadd(-1, base >> 12, (unsigned int)(size >> 12), 0). The shift
 *     happens in 64 bit before the cast, so the page count arrives intact.
 *
 *   The loss is in every CONSUMER, which recomputes bytes as
 *     mdev[devid].mdSize << 12
 *   in 32-bit `unsigned int` arithmetic (uint32_t does not promote to a wider
 *   type), so the byte size wraps modulo 2^32:
 *     bsd/dev/memdev.c:437       DKIOCGETBLOCKCOUNT - the number APFS uses
 *     bsd/dev/memdev.c:283,284,291,292  mdevstrategy end/trim bounds
 *     bsd/dev/memdev.c:245,248   mdevrw (character device only)
 *     bsd/dev/memdev.c:763       mdevgetrange (KDP core range only)
 *   (bsd/dev/memdev.c:540, the vmdx=/pmdx= boot-arg path, additionally casts
 *   the byte size with `(unsigned)size >> 12` before shifting; that path is
 *   not the one /chosen/memory-map uses.)
 *
 * CONSEQUENCE: no value the loader can publish helps. The device byte size the
 * guest derives is always (published_size & ~0xFFF) mod 2^32 < 4 GiB, while
 * APFS refuses to mount when the container size recorded in the image exceeds
 * the device size. A 9.41 GiB container therefore cannot mount on md0 whatever
 * the loader does, and no other device-tree property, unit or memory-map shape
 * reaches mdevadd.
 *
 * WHAT THIS DOES: it widens the two arithmetic chains that are on the mount
 * path, in the board's PRIVATE in-memory copy of the boot kernel cache only
 * (never the firmware file on disk), and only when the board's
 * md0-width-compat property is set:
 *
 *   mdevstrategy   (memdev.c:283..292) - one instruction. Apple's compiler
 *     common-subexpression-eliminates the four source uses into a single
 *     32-bit LSL, so widening that one shift fixes the end test, the
 *     past-end test and the trim.
 *   DKIOCGETBLOCKCOUNT (memdev.c:437) - three instructions: the ADD that
 *     folds the shift, the SUB #1 and the UDIV, each widened from 32 to 64
 *     bit (bit 31, the sf bit).
 *
 * The two sites are found by an anchor whose shape is derived from the
 * published source above: the uint32_t load at struct offset +8 (mdSize), the
 * int load at +16 (mdSecsize), and the register dataflow between them. Both
 * anchors are required to match EXACTLY ONCE in the kernel fileset entry's
 * __TEXT_EXEC; on any other count, or any structural mismatch, the buffer is
 * left completely untouched and the function fails. Nothing is written until
 * both sites are confirmed.
 *
 * WHAT IT REMOVES: the 32-bit wrap. With the patch, a ram disk of 4 GiB or
 * more reports its true size instead of (size mod 2^32). It removes no
 * authentication, signing, sealing or integrity check. It is a compatibility
 * measure, not Apple hardware or software fidelity: Apple's kernel does not
 * support an md ram disk of 4 GiB or more and this makes it do so.
 *
 * mdevrw (the /dev/rmd* character device) and mdevgetrange (the KDP core
 * range) are deliberately NOT patched: they are not on the root-mount path.
 * Those two therefore still see the wrapped size.
 */
typedef struct AppleModernMd0WidthPatch {
    /* File offsets of the first word of each anchor (for gates and logs). */
    uint64_t strategy_anchor;
    uint64_t blockcount_anchor;
    /* The patched instruction words, before and after. */
    uint32_t strategy_before;
    uint32_t strategy_after;
    uint32_t blockcount_before[3];
    uint32_t blockcount_after[3];
} AppleModernMd0WidthPatch;

bool apple_modern_kc_md0_width_compat(uint8_t *bootkc, size_t len,
                                      AppleModernMd0WidthPatch *out,
                                      Error **errp);

/*
 * Declared, opt-in root-mount read/write compatibility edit (off by default).
 *
 * ROOT CAUSE, from Apple's published source (apple-oss-distributions/xnu,
 * tag xnu-12377.121.6):
 *
 *   1. bsd/vfs/vfs_subr.c:1145-1150  vfs_rootmountalloc_internal() initializes
 *      the root mount structure before (*vfsp->vfc_mountroot)() runs:
 *        mp->mnt_vtable = vfsp;
 *        mp->mnt_op = vfsp->vfc_vfsops;
 *        mp->mnt_flag = MNT_RDONLY | MNT_ROOTFS;
 *        mp->mnt_vnodecovered = NULLVP;
 *        mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;
 *      During vfs_mountroot() (bsd/vfs/vfs_subr.c:1255), apfs_vfsop_mountroot
 *      -> apfs_mount_livefs rejects a writable mount if MNT_ROOTFS is already
 *      set on mp->mnt_flag. Immediately after vfs_mountroot() returns 0,
 *      bsd_init() (bsd/kern/bsd_init.c:918) sets MNT_ROOTFS on the root mount:
 *        mountlist.tqh_first->mnt_flag |= MNT_ROOTFS;
 *
 *   2. bsd/vfs/vfs_syscalls.c:1066-1092  __mac_mount() checks whether the
 *      covered vnode is root (`(vp->v_flag & VROOT) && (vp->v_mount->mnt_flag
 *      & MNT_ROOTFS)`), adds `MNT_UPDATE`, and under `#if SECURE_KERNEL`
 *      rejects any update that does not keep `MNT_RDONLY`:
 *        if ((flags & MNT_RDONLY) == 0) {
 *            error = EPERM;
 *            goto out;
 *        }
 *
 * WHAT THIS DOES: in the board's PRIVATE in-memory copy of the boot kernel
 * cache only (never the firmware file on disk), and only when the board's
 * root-rw-compat property is set, it locates:
 *   1. `vfs_rootmountalloc_internal` (`MOVZ Wa, #0xb7fe` ; `MOVK Wa, #0xdff0,
 *      LSL #16` ; `AND Wb, Wc, Wa` ; `MOVZ Wd, #0x4001` ; `ORR We, Wb, Wd` ;
 *      `STR We, [Xmp, #112]`) and changes `MOVZ Wd, #0x4001` to `MOVZ Wd, #0`
 *      so `vfs_mountroot()` mounts `/` read/write and `bsd_init()`
 *      (`bsd/kern/bsd_init.c:918`) then sets `MNT_ROOTFS` on `mp->mnt_flag`.
 *   2. The `__mac_mount` root-update check (`LDRB [Xvp, #84]` + `TBZ #0` +
 *      `LDRB [Xmp, #113]` + `TBNZ #6` branching to `ORR #0x10000` + `TBNZ #0` +
 *      `MOVZ #1`) and replaces `TBNZ Wflags, #0, L_ok` with an unconditional
 *      `B L_ok` to the same displacement so `/sbin/mount -u -w /` also succeeds.
 */
typedef struct AppleModernRootRwPatch {
    uint64_t rootmountalloc_anchor;
    uint32_t rootmountalloc_before;
    uint32_t rootmountalloc_after;
    uint64_t check_anchor;
    uint64_t update_anchor;
    uint32_t insn_before;
    uint32_t insn_after;
} AppleModernRootRwPatch;

bool apple_modern_kc_root_rw_compat(uint8_t *bootkc, size_t len,
                                    AppleModernRootRwPatch *out,
                                    Error **errp);

/*
 * Declared, opt-in TXM secure-channel constraint compatibility edit (off by
 * default).
 *
 * ROOT CAUSE, from Apple's published source (apple-oss-distributions/xnu,
 * tag xnu-12377.121.6, bsd/kern/code_signing/txm.c:672-706, 1237-1338) and
 * the documented Darwin-VM bring-up analysis
 * (maliosdark-docs_STATE_darwinvm_boot.md:731-737):
 *
 *   1. txm_associate_code_signature() invokes selector 38
 *      (kTXMKernelSelectorAssociateCodeSignature) to associate a registered
 *      code signature with a VM address-space region.
 *   2. On a board with no SEP/sepOS secure channel
 *      (kTXMKernelSelectorGetSecureChannelAddr), TXM's secure-channel
 *      constraint helper at VA 0xfffffff017033d00 reads the uninitialized
 *      secure-channel global at VA 0xfffffff017088db0 and returns 0, causing
 *      selector 38 to fail with error 42 ("disallowed due to secure channel
 *      constraints") and spin in an infinite page-fault retry loop for
 *      secure-channel-constrained processes.
 *
 * WHAT THIS DOES: in the board's PRIVATE in-memory copy of the TXM image only
 * (never the firmware file on disk), and only when the board's txm-sc-compat
 * property is set, it verifies the Mach-O __TEXT_EXEC and __DATA segments,
 * checks the prologue and ADRP-to-0xfffffff017088000 at VA 0xfffffff017033d00,
 * and writes `mov w0, #1 ; ret` at +4 and +8 so selector 38 records the region
 * association cleanly.
 */
typedef struct AppleModernTxmScPatch {
    uint64_t anchor;
    uint32_t prologue;
    uint32_t insn_before[2];
    uint32_t insn_after[2];
} AppleModernTxmScPatch;

bool apple_modern_txm_sc_compat(uint8_t *txm, size_t len,
                                AppleModernTxmScPatch *out,
                                Error **errp);

/*
 * Declared, opt-in IOUserClient sandbox and MACF compatibility edit (off by default).
 *
 * ROOT CAUSE: On iOS 27, the IOUserClient open path in IOUserClient.cpp
 * evaluates both a MACF check (mac_iokit_check_open) and a Sandbox check
 * (IOUC %s failed sandbox in process %s). For non-root processes such as
 * backboardd (UID 501 'mobile'), this check denies the creation of user clients
 * for IOMobileFramebuffer and IOSurface (kIOReturnNotPermitted 0xe00002c7),
 * leaving [CADisplay mainDisplay] uninitialized (0xFFFFFFFFFFFFFFFF) and preventing
 * display frame submission to the DCP.
 *
 * WHAT THIS DOES: in the board's PRIVATE in-memory copy of the boot kernel cache
 * only (never the firmware file on disk), and only when the board's
 * iouc-sandbox-compat property is set, it locates:
 *   1. The IOUserClient sandbox deny gate following the kIOReturnNotPermitted
 *      comparison and rewrites <DENY>'s first instruction to an unconditional
 *      branch to <ALLOW>.
 *   2. The preceding MACF check gate (CBZ W0, <ALLOW_MACF>) and rewrites it to
 *      an unconditional branch to <ALLOW_MACF>.
 */
typedef struct AppleModernIoucPatch {
    uint64_t sandbox_deny_anchor;
    uint32_t sandbox_deny_before;
    uint32_t sandbox_deny_after;
    uint64_t macf_gate_anchor;
    uint32_t macf_gate_before;
    uint32_t macf_gate_after;
} AppleModernIoucPatch;

bool apple_modern_kc_iouc_sandbox_compat(uint8_t *bootkc, size_t len,
                                         AppleModernIoucPatch *out,
                                         Error **errp);

/*
 * amfi-csstatus-platform-compat: NOP the platform-gate CBZ in csops_internal's
 * CS_OPS_STATUS handler so csops / csops_audittoken(CS_OPS_STATUS) always report
 * CS_PLATFORM_BINARY.  This makes every process satisfy launchd's RequireTrusted
 * event-stream subscriber check (whose "trusted" bit is the csops
 * CS_PLATFORM_BINARY flag), so backboardd's subscription to
 * com.apple.biome.compute.publisher is accepted and its AttentionAwareness
 * startup phase no longer wedges.  Trust-everything bring-up, not Apple fidelity.
 */
typedef struct AppleModernAmfiCsStatusPatch {
    uint64_t anchor;      /* file offset of the gating CBZ */
    uint32_t insn_before; /* 0x340000a0 cbz w0, #0x14 */
    uint32_t insn_after;  /* 0xd503201f nop */
} AppleModernAmfiCsStatusPatch;

bool apple_modern_kc_amfi_csstatus_platform_compat(uint8_t *bootkc, size_t len,
                                                   AppleModernAmfiCsStatusPatch *out,
                                                   Error **errp);

/*
 * platform-binary-force-compat: force csproc_get_platform_binary() to return 1
 * so EVERY in-kernel platform-binary reader (csops, audit-token resolution,
 * AMFI, sandbox, debug gates) treats every process as a platform binary.
 * Broader than amfi-csstatus-platform-compat (which only changes the value
 * csops reports to userspace); use when a non-csops consumer also needs the
 * platform status (e.g. launchd's RequireTrusted subscriber-trust cache if it
 * is not populated through the csops CS_OPS_STATUS path).  Trust-everything
 * bring-up, not Apple fidelity.
 */
typedef struct AppleModernPlatBinPatch {
    uint64_t anchor;         /* file offset of the leading bti c */
    uint32_t insn_before[2]; /* cbz x0 ; ldr x16,[x0,#0x538] */
    uint32_t insn_after[2];  /* mov w0,#1 ; ret */
} AppleModernPlatBinPatch;

bool apple_modern_kc_platform_binary_force_compat(uint8_t *bootkc, size_t len,
                                                  AppleModernPlatBinPatch *out,
                                                  Error **errp);

/*
 * rootvp-auth-skip-compat: let the guest boot in NORMAL mode (rootdev=md0)
 * instead of restore mode (rd=md0).  bsd_init() skips the root-vnode
 * authentication iff bsd_rooted_ramdisk() is true, which only holds when the
 * boot-arg is literally "rd=md0".  With "rootdev=md0" (which launchd does NOT
 * treat as restore, so it runs the normal boot-tasks) the detector returns 0,
 * the VNOP_IOCTL root-auth query runs on the plain ramdisk, returns nonzero,
 * and the kernel panics "rootvp not authenticated after mounting @bsd_init.c:976".
 * This patch turns the ramdisk-skip branch (tbnz w0,#0,<skip>) into an
 * unconditional branch so the auth check is always skipped -- byte-for-byte the
 * same path rd=md0 already takes.  Pair with -machine root-arg rootdev=md0.
 * Compatibility (ramdisk root without the rd= restore match), not Apple fidelity.
 */
typedef struct AppleModernRootvpSkipPatch {
    uint64_t anchor;      /* file offset of the ramdisk-skip tbnz */
    uint32_t insn_before; /* 0x37000200 tbnz w0, #0, <skip> */
    uint32_t insn_after;  /* 0x14000010 b <skip> */
} AppleModernRootvpSkipPatch;

bool apple_modern_kc_rootvp_auth_skip_compat(uint8_t *bootkc, size_t len,
                                             AppleModernRootvpSkipPatch *out,
                                             Error **errp);

/*
 * vekd-unenc-data-compat: NOP the apfs kext's "unencrypted data volume is not
 * allowed" guard so a PLAIN (software-keyed) Data volume mounts without the
 * role64+unencrypted panic.  On the pinned BootKC the deciding instruction is
 * in com.apple.filesystems.apfs __TEXT_EXEC at VA 0xfffffff00a9cfc70:
 *     tbnz w8, #0, 0xfffffff00a9cfc84   ; 0x370000a8 -> panic branch
 * Replaced with a NOP (0xd503201f) so the branch is never taken.  Mirrors the
 * one-NOP neutralization ZCode qualified as bootkc-vekd-compat; applied to the
 * in-memory cache (trustcache stays valid).  Compatibility, not Apple fidelity.
 */
typedef struct AppleModernVekdPatch {
    uint64_t anchor;      /* file offset of the unencrypted-data tbnz */
    uint32_t insn_before; /* 0x370000a8 tbnz w8, #0, <panic> */
    uint32_t insn_after;  /* 0xd503201f nop */
} AppleModernVekdPatch;

bool apple_modern_kc_vekd_unenc_data_compat(uint8_t *bootkc, size_t len,
                                            AppleModernVekdPatch *out,
                                            Error **errp);

/*
 * keystore-persona-stub-compat (OPT-IN, OFF by default): force the
 * AppleSEPKeyStore persona-UUID -> volume mapping to SUCCEED, so persona type 6
 * bring-up (usermanagerd) does not fail with 0xe007c022 when the emulator has no
 * real SEP keybag populated with the persona UUID.  Only sound for a PLAIN
 * (unencrypted) Data volume, where no real volume key is needed.  On the pinned
 * BootKC the fail path in com.apple.driver.AppleSEPKeyStore is:
 *     0xfffffff0095f3ef0  mov  w21, #0xc022     (0x52980455)
 *     0xfffffff0095f3ef4  movk w21, #0xe007,16  (0x72bc00f5)  => w21 = 0xe007c022 (err)
 * Patched so the fail path returns 0 (success):
 *     mov w21, #0 (0x52800015) ; nop (0xd503201f)
 * Grok P3 anchors; apply in-memory (trustcache stays valid).  Compatibility, not
 * Apple fidelity.  Grok cautions this "lies" to callers, so it stays opt-in and is
 * validated only once a real Data volume mounts (then persona-6 is testable).
 */
typedef struct AppleModernKeystoreStubPatch {
    uint64_t anchor;       /* file offset of the first patched insn */
    uint32_t insn_before0; /* 0x52980455 mov w21,#0xc022 */
    uint32_t insn_after0;  /* 0x52800015 mov w21,#0      */
    uint32_t insn_before1; /* 0x72bc00f5 movk w21,#0xe007,lsl#16 */
    uint32_t insn_after1;  /* 0xd503201f nop             */
} AppleModernKeystoreStubPatch;

bool apple_modern_kc_keystore_persona_stub_compat(uint8_t *bootkc, size_t len,
                                                  AppleModernKeystoreStubPatch *out,
                                                  Error **errp);

#endif

