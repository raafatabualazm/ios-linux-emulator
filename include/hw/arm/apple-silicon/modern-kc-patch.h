/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_KC_PATCH_H
#define HW_ARM_APPLE_MODERN_KC_PATCH_H

#include "qapi/error.h"
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

#endif
