/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_BOOT_METADATA_H
#define HW_ARM_APPLE_MODERN_BOOT_METADATA_H

#include "hw/arm/apple-silicon/modern-boot-layout.h"

#define APPLE_MODERN_COMMAND_LINE_SIZE 1024

typedef struct AppleModernBootVideo {
    uint64_t base_address, display, row_bytes, width, height, depth;
} AppleModernBootVideo;

#define APPLE_MODERN_MAX_ADT_OVERRIDES 64
#define APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES 4096

/*
 * One property to set on an existing node: replace it when the node already
 * carries it, otherwise append it. Used for values iBoot normally computes
 * at hand-off (for example /arm-io/pmgr voltage-states*) when the board
 * supplies them from a declared profile.
 */
typedef struct AppleModernAdtOverride {
    const char *path;          /* canonical slash path, node must exist once */
    const char *name;          /* 1..31 bytes, unique within the node */
    const uint8_t *value;      /* size bytes */
    uint32_t size;             /* 1..APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES */
} AppleModernAdtOverride;

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
    /*
     * Acknowledge register offset to publish as /arm-io/aic
     * "aic-iack-offset" (u64), replacing any value the stock tree carries.
     * XNU's AppleInterruptControllerV3 reads only that property for the
     * offset, defaults it to zero and panics when it is still zero, so the
     * served tree and our controller must agree. Zero leaves the node alone,
     * and a nonzero value requires /arm-io/aic to exist.
     */
    uint32_t aic_iack_offset;
    /*
     * Optional property overrides. Every node must exist exactly once and the
     * (path, name) pairs must be unique. Nodes the loader already rewrites
     * (/chosen, /chosen/memory-map, /vram, /arm-io/aic) are refused; the
     * property named "name" is refused so a node can never be renamed.
     */
    const AppleModernAdtOverride *overrides;
    size_t override_count;
    /*
     * Declared, default off. Give every node whose "compatible" list contains
     * "dart,t8110" a 4-byte "dart-id" property: 0, 1, 2, ... in ADT order
     * (depth-first, as the nodes appear in the blob), replacing a property the
     * input already carries. Provenance: attested (measured in a guest) that
     * SPTM's t8110dart_bootstrap_instance panics "error -1 getting dart-id"
     * for a restored dart,t8110 node without it, and that none of the 25 nodes
     * in the stock iPhone17,3 tree carries one; analogy (Cody Ho's SPTM DART
     * notes, Darwin-VM dt_fixup) that it is the logical DART object id every
     * SPTM DART endpoint takes in x0, so it must be unique; declared that
     * iBoot numbers in ADT order from zero, which is not measured.
     * Keyed on the INPUT tree: a tree that strips every DART compatible (the
     * Darwin-derived one) has no such node and the build is refused, as is an
     * override that names "dart-id". Nothing else in the tree changes.
     */
    bool assign_dart_ids;
} AppleModernBootMetadataInput;

typedef struct AppleModernBootMetadata {
    AppleModernBootLayout layout;
    uint8_t *dtree;
    size_t dtree_size;
    uint8_t bootargs[APPLE_MODERN_BOOTARGS_SIZE];
    /* Ordinary 8-byte offsets header followed by the unchanged stock catalog. */
    uint8_t *trustcache;
    size_t trustcache_size;
    /* Number of dart-id properties generated (zero unless assign_dart_ids). */
    uint32_t dart_id_count;
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
