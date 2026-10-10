/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_IMAGE_PATCH_H
#define HW_ARM_APPLE_MODERN_IMAGE_PATCH_H

/*
 * Declared, opt-in, anchored image-patch facility for the apple-modern board.
 *
 * Every patch is one reviewable table entry: an ANCHOR byte pattern (with an
 * optional per-byte mask), the REPLACEMENT bytes and where they are written
 * inside the matched anchor, the EXPECTED number of matches (normally one),
 * a one-line statement of what the patch changes, and a plain statement of
 * which security property or behaviour it removes.
 *
 * Discipline enforced here, so no later patch can skip it:
 *  - Patches apply ONLY to a caller-owned in-memory copy of a decoded image.
 *    This facility never opens, maps or writes a file. The caller verifies the
 *    on-disk inputs are unchanged after calling (modern-machine.c re-stats).
 *  - A patch is applied only if its anchor is found EXACTLY expected_count
 *    times; otherwise nothing is written and the facility fails with a precise
 *    message naming the patch (anchor missing, found N != expected, or the
 *    replacement would not fit the anchor span).
 *  - Validation of every selected patch runs BEFORE any byte is written, so a
 *    failure leaves the buffer pristine.
 *  - The set of patches to apply is chosen by an explicit board option; the
 *    default board selects no set and is byte-identical to an unpatched board.
 *
 * It is a compatibility/bring-up facility, NOT Apple hardware fidelity: it
 * changes guest image bytes. The caller announces every applied patch on the
 * emulator log in the project's "declared profile" warning style and exposes
 * the applied list through QOM so gates can read it.
 */

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#else
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/modern-boot-layout.h"

/* Upper bound on patches applied in one board instance (QOM list + core). */
#define APPLE_MODERN_MAX_IMAGE_PATCHES 64

typedef struct AppleModernImagePatch {
    /* Unique within its set; used in log lines, errors and the QOM list. */
    const char *name;
    /* Which decoded image this entry targets (BOOTKC/SPTM/TXM/...). */
    AppleModernImage image;
    /* Byte pattern that locates the edit site. */
    const uint8_t *anchor;
    /* NULL, or a per-byte mask: a match requires (buf[i]&mask[i])==anchor[i].
     * Every anchor byte must already satisfy anchor[i]&mask[i]==anchor[i]. */
    const uint8_t *anchor_mask;
    size_t anchor_len;
    /* Bytes written verbatim at anchor_offset within each matched anchor. */
    const uint8_t *replacement;
    size_t replacement_len;
    size_t replace_offset;
    /* Required number of anchor matches in the image (normally 1). */
    size_t expected_count;
    /* One line: what this patch changes. */
    const char *changes;
    /* Plainly: which security property or behaviour this removes. */
    const char *removes;
} AppleModernImagePatch;

typedef struct AppleModernImagePatchSet {
    /* Value of the board option that selects this set. */
    const char *name;
    const AppleModernImagePatch *patches;
    size_t patch_count;
} AppleModernImagePatchSet;

typedef struct AppleModernImagePatchApplied {
    const char *name;
    const char *changes;
    const char *removes;
    AppleModernImage image;
    /* Offset within the image where the replacement was written. */
    uint64_t offset;
    size_t replacement_len;
} AppleModernImagePatchApplied;

typedef struct AppleModernImagePatchResult {
    AppleModernImagePatchApplied entries[APPLE_MODERN_MAX_IMAGE_PATCHES];
    size_t count;
} AppleModernImagePatchResult;

/* Look up a set by option value, or NULL when the name is unknown. */
const AppleModernImagePatchSet *apple_modern_image_patch_set(const char *name);

/* Comma-separated list of supported set names, for error messages. */
const char *apple_modern_image_patch_set_names(void);

/*
 * Apply every patch in `set` that targets `image` to buf[0..len). Appends one
 * entry to `result` per applied patch. Validates ALL targeted patches first;
 * on any failure writes nothing, leaves buf and result untouched for the
 * failed image, and returns false with `errp` naming the patch and reason.
 *
 * The caller invokes this once per decoded image; `result` accumulates across
 * images up to APPLE_MODERN_MAX_IMAGE_PATCHES total.
 */
bool apple_modern_image_patch_apply_image(const AppleModernImagePatchSet *set,
                                          AppleModernImage image,
                                          uint8_t *buf, size_t len,
                                          AppleModernImagePatchResult *result,
                                          Error **errp);

#endif
