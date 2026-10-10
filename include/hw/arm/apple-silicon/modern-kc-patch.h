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

#endif
