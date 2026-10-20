/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_BOOT_METADATA_H
#define HW_ARM_APPLE_MODERN_BOOT_METADATA_H

#include "hw/arm/apple-silicon/modern-boot-layout.h"

#define APPLE_MODERN_COMMAND_LINE_SIZE 1024

typedef struct AppleModernBootVideo {
    uint64_t base_address, display, row_bytes, width, height, depth;
} AppleModernBootVideo;

/* Ten compatibility groups need 90 rows, plus bounded board profiles. */
#define APPLE_MODERN_MAX_ADT_OVERRIDES 128
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

#define APPLE_MODERN_MAX_ADT_NODE_PROPS 64

/*
 * One property of a synthesized node. Unlike an override a zero-length
 * property is allowed, because real ADT nodes carry presence-only properties
 * (/arm-io/sgx "procedural-antialiasing") and the point of a synthesized node
 * is to reproduce a pinned stock one byte for byte.
 */
typedef struct AppleModernAdtNodeProp {
    const char *name;          /* 1..31 bytes, unique within the node */
    const uint8_t *value;      /* size bytes; NULL only when size is zero */
    uint32_t size;             /* 0..APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES */
} AppleModernAdtNodeProp;

/*
 * One whole node to append as the last child of an existing node. An override
 * can only add a property to a node that already exists, so a tree that
 * DELETES a node the kernel matches on cannot be repaired with overrides; this
 * is the other half of that facility. The parent must exist exactly once and
 * must not already have a child of this name, and the loader-owned nodes are
 * refused (their own property generation assumes their child list).
 */
typedef struct AppleModernAdtNode {
    const char *parent;        /* canonical slash path, node must exist once */
    const char *name;          /* node name, matching the "name" property */
    const AppleModernAdtNodeProp *props;
    size_t prop_count;         /* 1..APPLE_MODERN_MAX_ADT_NODE_PROPS */
} AppleModernAdtNode;

typedef struct AppleModernBootMetadataInput {
    const AppleModernBootInput *components;
    /* Length excludes NUL; bytes must have no embedded NUL. NULL/0 is empty. */
    const char *command_line;
    size_t command_line_length;
    bool has_mte;
    /*
     * Optional GPU (UAT) carveout, in bytes; zero disables it.
     *
     * SPTM's unified address translator refuses to register a GPU IO range
     * made of pages XNU manages -- measured, with the GPU node served and the
     * handoff properties pointing into ordinary DRAM:
     *   "iommu_bootstrap_register_io_range: IOMMU uat (3): Attempted to
     *    register managed page as an IO range 0x0000010500000000 128"
     * (and, with the properties absent, "uat_get_dt_prop: error -1 looking up
     * gfx-shared-region-base"; both are SPTM panics at EL2 before the UART
     * exists, so they present as a guest hang with zero serial output).
     *
     * So the GPU regions must live outside managed DRAM. This reserves them
     * exactly the way the framebuffer handoff does: shrink memSize and place
     * the carveout at the resulting boundary, adding no untyped bootstrap
     * pages below topOfKernelData. Must be a multiple of the 16 KiB UAT
     * granule; the framebuffer alignment is used so the two tails stack
     * without breaking the framebuffer's own alignment check.
     */
    uint64_t gfx_carveout_size;
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
     * Publish /chosen "sepfw-load-at-boot" = 0 (u32), replacing the template
     * value: declares that no SEP firmware runs (board option sepfw-absent).
     * /chosen is loader-owned, so this cannot go through the override list.
     */
    bool chosen_sepfw_absent;
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
    /*
     * Optional, default NULL: one synthesized node appended to an existing
     * parent. Refused when the parent is missing or ambiguous, when it already
     * has a child of that name, or when the node is malformed.
     */
    const AppleModernAdtNode *added_node;
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
