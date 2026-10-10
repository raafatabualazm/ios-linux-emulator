/*
 * Declared, opt-in, anchored image-patch facility for the apple-modern board.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * See modern-image-patch.h for the contract. This file holds the generic
 * apply engine and the named patch sets. Adding a patch is one table entry;
 * no bespoke scanning code is written per patch.
 */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/modern-image-patch.h"

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
/* Test adapter only; production uses QEMU's Error implementation. Mirrors the
 * same static shim in modern-boot-layout.c (error_free is shared from there). */
static void error_setg(Error **errp, const char *format, ...)
{
    va_list args;
    if (!errp) {
        return;
    }
    if (*errp) {
        abort();
    }
    *errp = calloc(1, sizeof(**errp));
    if (!*errp) {
        abort();
    }
    va_start(args, format);
    vsnprintf((*errp)->message, sizeof((*errp)->message), format, args);
    va_end(args);
}
#endif

/*
 * -------------------------------------------------------------------------
 * Patch sets.
 *
 * Each set is one named collection selected by the board's image-patches
 * option. The default board selects no set, so it is byte-identical to an
 * unpatched board.
 * -------------------------------------------------------------------------
 */

/*
 * Demonstration set "demo": a single, trivial, text-only patch that exercises
 * the mechanism end to end. It rewrites the benign, exactly-once BootKC log
 * string "Warning: arc4random not implemented" to an identically sized marker.
 * The arc4random stub itself is untouched; only the printed text changes. It
 * removes no security property and changes no behaviour. It is here solely so
 * a gate can prove the facility finds, replaces, announces and lists a patch.
 */
static const uint8_t demo_arc4random_anchor[] =
    "Warning: arc4random not implemented";
static const uint8_t demo_arc4random_replacement[] =
    "Inferno demo image-patch (harmless)";

static const AppleModernImagePatch demo_patches[] = {
    {
        .name = "demo-log-string",
        .image = APPLE_MODERN_BOOTKC,
        .anchor = demo_arc4random_anchor,
        .anchor_mask = NULL,
        /* sizeof - 1 drops the C string terminator from the anchor. */
        .anchor_len = sizeof(demo_arc4random_anchor) - 1,
        .replacement = demo_arc4random_replacement,
        .replacement_len = sizeof(demo_arc4random_replacement) - 1,
        .replace_offset = 0,
        .expected_count = 1,
        .changes = "rewrites the benign BootKC log string "
                   "'Warning: arc4random not implemented' to a same-length "
                   "demo marker",
        .removes = "nothing (text-only demonstration; no behavioural or "
                   "security effect)",
    },
};

static const AppleModernImagePatchSet patch_sets[] = {
    { "demo", demo_patches, sizeof(demo_patches) / sizeof(demo_patches[0]) },
};

#define PATCH_SET_COUNT (sizeof(patch_sets) / sizeof(patch_sets[0]))

const AppleModernImagePatchSet *apple_modern_image_patch_set(const char *name)
{
    if (!name) {
        return NULL;
    }
    for (size_t i = 0; i < PATCH_SET_COUNT; i++) {
        if (!strcmp(patch_sets[i].name, name)) {
            return &patch_sets[i];
        }
    }
    return NULL;
}

const char *apple_modern_image_patch_set_names(void)
{
    /* Built once from the table; grows automatically as sets are added. */
    static char names[256];
    if (!names[0]) {
        size_t used = 0;
        for (size_t i = 0; i < PATCH_SET_COUNT && used + 1 < sizeof(names); i++) {
            int n = snprintf(names + used, sizeof(names) - used, "%s%s",
                             i ? ", " : "", patch_sets[i].name);
            if (n < 0) {
                break;
            }
            used += (size_t)n;
        }
    }
    return names;
}

/*
 * -------------------------------------------------------------------------
 * Generic apply engine.
 * -------------------------------------------------------------------------
 */

/* True if the anchor matches buf[pos..], honouring an optional mask. */
static bool anchor_matches(const AppleModernImagePatch *p,
                           const uint8_t *buf, uint64_t pos)
{
    if (p->anchor_mask) {
        for (size_t k = 0; k < p->anchor_len; k++) {
            if ((buf[pos + k] & p->anchor_mask[k]) != p->anchor[k]) {
                return false;
            }
        }
        return true;
    }
    return memcmp(buf + pos, p->anchor, p->anchor_len) == 0;
}

/*
 * Count anchor matches in buf[0..len), up to `cap`+1 so "more than expected"
 * is detectable without scanning further than needed. first_match is set to
 * the offset of the first match (if any).
 */
static size_t count_matches(const AppleModernImagePatch *p,
                            const uint8_t *buf, size_t len, size_t cap,
                            uint64_t *first_match)
{
    size_t count = 0;
    if (p->anchor_len == 0 || p->anchor_len > len) {
        return 0;
    }
    for (uint64_t pos = 0; pos + p->anchor_len <= len; pos++) {
        /* Skip ahead on the first byte when there is no mask (fast path). */
        if (!p->anchor_mask && buf[pos] != p->anchor[0]) {
            continue;
        }
        if (anchor_matches(p, buf, pos)) {
            if (count == 0 && first_match) {
                *first_match = pos;
            }
            count++;
            if (count > cap) {
                return count;
            }
        }
    }
    return count;
}

/* Reject a malformed table entry (programmer error caught before any write). */
static bool validate_entry(const AppleModernImagePatch *p, Error **errp)
{
    if (!p->name || !p->anchor || !p->replacement || !p->changes ||
        !p->removes) {
        error_setg(errp, "image-patch: malformed entry (missing field)");
        return false;
    }
    if (p->anchor_len == 0 || p->replacement_len == 0) {
        error_setg(errp, "image-patch '%s': empty anchor or replacement",
                   p->name);
        return false;
    }
    if (p->expected_count == 0) {
        error_setg(errp, "image-patch '%s': expected_count must be >= 1",
                   p->name);
        return false;
    }
    /*
     * A same-size, in-place edit: the replacement must fit entirely inside the
     * matched anchor span. A replacement that would run past the anchor is a
     * length mismatch and is refused.
     */
    if (p->replace_offset > p->anchor_len ||
        p->replacement_len > p->anchor_len - p->replace_offset) {
        error_setg(errp, "image-patch '%s': replacement (%zu bytes at offset "
                   "%zu) does not fit the %zu-byte anchor",
                   p->name, p->replacement_len, p->replace_offset,
                   p->anchor_len);
        return false;
    }
    if (p->anchor_mask) {
        for (size_t k = 0; k < p->anchor_len; k++) {
            if ((p->anchor[k] & p->anchor_mask[k]) != p->anchor[k]) {
                error_setg(errp, "image-patch '%s': anchor byte %zu has bits "
                           "outside its mask", p->name, k);
                return false;
            }
        }
    }
    return true;
}

bool apple_modern_image_patch_apply_image(const AppleModernImagePatchSet *set,
                                          AppleModernImage image,
                                          uint8_t *buf, size_t len,
                                          AppleModernImagePatchResult *result,
                                          Error **errp)
{
    uint64_t matches[APPLE_MODERN_MAX_IMAGE_PATCHES];
    const AppleModernImagePatch *targeted[APPLE_MODERN_MAX_IMAGE_PATCHES];
    size_t n = 0;
    /* Result slots already used by earlier images, plus those this image will
     * need; pass 2 writes one entry per MATCH (see the budget check below). */
    size_t entries;

    if (!set || !buf || !result) {
        error_setg(errp, "image-patch: null argument");
        return false;
    }
    if (result->count > APPLE_MODERN_MAX_IMAGE_PATCHES) {
        error_setg(errp, "image-patch: invalid result count %zu (max %d)",
                   result->count, APPLE_MODERN_MAX_IMAGE_PATCHES);
        return false;
    }
    entries = result->count;

    /*
     * Pass 1 (no writes): select the patches for this image, validate each
     * entry, and require the anchor to appear exactly expected_count times.
     * Any failure here refuses the whole image with the buffer untouched.
     */
    for (size_t i = 0; i < set->patch_count; i++) {
        const AppleModernImagePatch *p = &set->patches[i];
        uint64_t first = 0;
        size_t count;

        if (p->image != image) {
            continue;
        }
        if (n >= APPLE_MODERN_MAX_IMAGE_PATCHES ||
            result->count + n >= APPLE_MODERN_MAX_IMAGE_PATCHES) {
            error_setg(errp, "image-patch: too many patches (max %d)",
                       APPLE_MODERN_MAX_IMAGE_PATCHES);
            return false;
        }
        if (!validate_entry(p, errp)) {
            return false;
        }
        count = count_matches(p, buf, len, p->expected_count, &first);
        if (count == 0) {
            error_setg(errp, "image-patch '%s': anchor not found (expected %zu)",
                       p->name, p->expected_count);
            return false;
        }
        if (count != p->expected_count) {
            /* count_matches stops at expected_count+1, so a larger true count
             * is reported as "more than expected". */
            if (count > p->expected_count) {
                error_setg(errp, "image-patch '%s': anchor found more than the "
                           "expected %zu times", p->name, p->expected_count);
            } else {
                error_setg(errp, "image-patch '%s': anchor found %zu times "
                           "(expected %zu)", p->name, count, p->expected_count);
            }
            return false;
        }
        /*
         * Budget the RESULT ENTRIES, which pass 2 writes one per MATCH, not one
         * per patch: a single entry with expected_count > 1 consumes that many
         * slots of result->entries[]. Checking it here keeps the two-pass
         * contract - every refusal happens before any byte of the image is
         * written - and it is the bound that the per-patch check below cannot
         * express. (Found by the independent verifier of 413e27c, which
         * reproduced a stack-buffer-overflow with a 70-match entry.)
         */
        if (p->expected_count > APPLE_MODERN_MAX_IMAGE_PATCHES - entries) {
            error_setg(errp, "image-patch '%s': %zu matches exceed the %d "
                       "result slots left", p->name, p->expected_count,
                       (int)(APPLE_MODERN_MAX_IMAGE_PATCHES - entries));
            return false;
        }
        entries += p->expected_count;
        targeted[n] = p;
        matches[n] = first;
        n++;
    }

    /*
     * Pass 2: write. For expected_count==1 the single match offset is known;
     * for a higher expected_count, re-scan and write every match so the table
     * stays the single source of truth.
     */
    for (size_t j = 0; j < n; j++) {
        const AppleModernImagePatch *p = targeted[j];
        if (p->expected_count == 1) {
            uint64_t at = matches[j] + p->replace_offset;
            memcpy(buf + at, p->replacement, p->replacement_len);
            result->entries[result->count++] =
                (AppleModernImagePatchApplied){ p->name, p->changes, p->removes,
                                                image, at, p->replacement_len };
        } else {
            size_t applied = 0;
            for (uint64_t pos = 0; pos + p->anchor_len <= len; pos++) {
                if (!p->anchor_mask && buf[pos] != p->anchor[0]) {
                    continue;
                }
                if (!anchor_matches(p, buf, pos)) {
                    continue;
                }
                uint64_t at = pos + p->replace_offset;
                memcpy(buf + at, p->replacement, p->replacement_len);
                result->entries[result->count++] =
                    (AppleModernImagePatchApplied){ p->name, p->changes,
                                                    p->removes, image, at,
                                                    p->replacement_len };
                applied++;
            }
            /* Pass 1 already proved the count; this is a belt-and-braces guard. */
            if (applied != p->expected_count) {
                error_setg(errp, "image-patch '%s': applied %zu of %zu matches",
                           p->name, applied, p->expected_count);
                return false;
            }
        }
    }
    return true;
}
