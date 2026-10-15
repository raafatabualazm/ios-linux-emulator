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
 * Declared, opt-in HID static-config edit (off by default).
 *
 * ROOT CAUSE (established by read-only RE of BootKC a36b9241..., recorded in
 * modern-emulator/.../re/fifo-protocol.md and the re/dis disassembly):
 *
 *   iOS 27 multitouch runs over AppleHIDTransportDeviceFIFO. The transport
 *   stalls at "ERROR!! No protocol specified" (AppleHIDTransportDevice::
 *   powerHasChanged, unslid 0xfffffff008e1e11c) because device+0xb0, the
 *   protocol object, is NULL. Only AppleHIDTransportDevice::cacheConfig
 *   (0xfffffff008e1e810, device vtable +0x570) sets device+0xb0, from an
 *   OSString "Protocol" key in a config OSDictionary it is handed. On a board
 *   with no live MTP firmware download the only reachable caller that can hand
 *   it one is AppleHIDTransportDevice::startGated (0xfffffff008e1c368), which
 *   at 0xfffffff008e1ca30 calls cacheConfig(getStaticConfig()). getStaticConfig
 *   (FIFO device vtable +0x6e8) is a 12-byte stub "bti c; movz x0,#0; ret" that
 *   returns NULL in all five device classes, so no config ever arrives. The
 *   startGated guard at 0xfffffff008e1c9c4 takes the static branch when
 *   device+0xb8 == NULL (true: /arm-io/dockchannel-mtp/mtp-transport carries no
 *   "bootloader-type") or when copyProperty("use-static-config", ...parents)
 *   is non-NULL.
 *
 * WHAT THIS DOES: in the board's PRIVATE in-memory copy of the boot kernel
 * cache only (never the firmware file on disk), and only when the board's
 * hid-static-config property is set, it rewrites getStaticConfig so it returns
 * an OSDictionary built from an embedded XML plist, equivalent to
 *   adrp/add x0, <embedded XML> ; movz x1, #0 ; b OSUnserializeXML
 * The 12-byte stub cannot hold that sequence, so its first instruction (the
 * "bti c" landing pad required by the indirect blraa call) is KEPT and its
 * second instruction is replaced with a single "b <cave>" into a code cave in
 * the trailing zero padding of the cache __TEXT_EXEC; the cave holds the real
 * instruction sequence and the NUL-terminated XML string. OSUnserializeXML is
 * reached through AppleHIDTransport's existing GOT import thunk (unslid
 * 0xfffffff008e99c24), whose shape and resolved target are verified. The
 * returned OSDictionary has refcount 1 and is released by startGated at
 * 0xfffffff008e1ca60 (vtable +0x28), matching getStaticConfig's contract (no
 * retain). The patch site is the UNIQUE table in the FIFO kext __DATA_CONST
 * whose +0x6e8 slot targets the "bti c; movz x0,#0; ret" stub in the FIFO
 * __TEXT_EXEC and whose +0x570 slot targets a prologue in the base
 * AppleHIDTransport __TEXT_EXEC (inherited cacheConfig); nothing is written
 * unless exactly one such table is found, every bound is checked, and the cave
 * is confirmed to be all-zero padding.
 *
 * XML PAYLOAD: the config dict carries the real MTP_SYS[0].Config values from
 * the pinned FTAB personality (re/mtpfw/iokt.json): Client, Version,
 * Allocation, Protocol=SCMFIFO, MaxReadSize/MaxWriteSize=16384, MemoryFifos and
 * the four Interfaces with their scalar/flag keys. "Protocol" is what
 * cacheConfig casts to an OSString and resolves to the real class
 * AppleHIDTransportProtocolSCMFIFO; MaxReadSize/MaxWriteSize/Interfaces/
 * MemoryFifos are what that protocol's configure method (protocol vtable +0x600,
 * called from cacheConfig at 0xfffffff008e1e9d8) consumes. The deep per-
 * interface Reporters/Channels/reset-sequence sub-arrays are OMITTED: configure
 * stores the Interfaces array by reference and logs its count but never walks
 * them (verified in the disassembly), every key it reads is cast-and-null-
 * checked or defaulted, and the full dict (~58 KiB of XML) does not fit in any
 * provably-unused code cave.
 *
 * WHAT IT REMOVES: nothing. It adds no path around any signing, trust-cache,
 * AMFI, pmap_cs or page-in enforcement check; it replaces one config-provider
 * stub and adds otherwise-unused code to segment padding. It is a compatibility
 * measure, not Apple hardware or software fidelity.
 */
typedef struct AppleModernHidStaticConfigPatch {
    uint64_t stub_anchor;    /* file offset of the getStaticConfig stub (G) */
    uint64_t stub_va;        /* unslid VA of the stub (orientation) */
    uint32_t stub_before;    /* word at G+4 before the patch (movz x0,#0) */
    uint32_t stub_after;     /* word at G+4 after the patch (b <cave>) */
    uint64_t vtable_va;      /* unslid VA of the FIFO device vtable */
    uint64_t cave_off;       /* file offset of the code cave */
    uint64_t cave_va;        /* unslid VA of the code cave */
    uint64_t xml_off;        /* file offset of the embedded XML string */
    uint64_t xml_va;         /* unslid VA of the embedded XML string */
    uint32_t xml_len;        /* XML byte count, excluding the NUL terminator */
    uint64_t thunk_va;       /* unslid VA of the OSUnserializeXML import thunk */
    uint32_t cave_insns[4];  /* adrp x0 ; add x0 ; movz x1,#0 ; b thunk */
} AppleModernHidStaticConfigPatch;

bool apple_modern_kc_hid_static_config(uint8_t *bootkc, size_t len,
                                       AppleModernHidStaticConfigPatch *out,
                                       Error **errp);

#endif

