/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_BOOT_METADATA_H
#define HW_ARM_APPLE_MODERN_BOOT_METADATA_H

#include "hw/arm/apple-silicon/modern-boot-layout.h"

#define APPLE_MODERN_COMMAND_LINE_SIZE 1024

typedef struct AppleModernBootVideo {
    uint64_t base_address, display, row_bytes, width, height, depth;
} AppleModernBootVideo;

typedef struct AppleModernBootMetadataInput {
    const AppleModernBootInput *components;
    /* Length excludes NUL; bytes must have no embedded NUL. NULL/0 is empty. */
    const char *command_line;
    size_t command_line_length;
    bool has_mte;
    /* Without a framebuffer reservation this retains the explicit ABI values.
     * Otherwise zero selects the derived text-console geometry; a nonzero
     * explicit description must exactly match that reserved framebuffer.
     */
    AppleModernBootVideo video;
    uint64_t boot_flags;
    /* Zero selects the computed reservation; a smaller budget is allowed. */
    size_t dtree_capacity_limit;
} AppleModernBootMetadataInput;

typedef struct AppleModernBootMetadata {
    AppleModernBootLayout layout;
    uint8_t *dtree;
    size_t dtree_size;
    uint8_t bootargs[APPLE_MODERN_BOOTARGS_SIZE];
    /* Ordinary 8-byte offsets header followed by the unchanged stock catalog. */
    uint8_t *trustcache;
    size_t trustcache_size;
} AppleModernBootMetadata;

/*
 * Revalidate components/layout and serialize owned normal boot metadata.
 * Keep all original ADT devices and unrelated properties. An enabled boot
 * framebuffer updates an existing /vram/reg and PurpleGfxMem to its reserved
 * address/size, after any MTE adjustment, and excludes it from boot_args.memSize.
 * No guest-memory
 * writes, executable/security patches, signature checks or guest execution.
 * Optional ramdisk matching/provenance must be established by the caller.
 * Output must be fresh or previously cleared. Disjoint failures clear output;
 * forbidden input/output aliases are rejected without touching either.
 */
bool apple_modern_boot_metadata_build(const AppleModernBootMetadataInput *input,
                                     AppleModernBootMetadata *output,
                                     Error **errp);
void apple_modern_boot_metadata_clear(AppleModernBootMetadata *output);

/*
 * Full bounded traversal, then borrowed property bytes. Canonical slash paths
 * ("/" for root); missing/ambiguous paths or malformed trees return an error.
 * Caller keeps the source blob alive. Value must not overlap blob/path/name.
 */
bool apple_modern_adt_property(AppleModernBlob dtree, const char *path,
                              const char *name, AppleModernBlob *value,
                              Error **errp);

#endif
