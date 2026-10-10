/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_COMPAT_GROUPS_H
#define HW_ARM_APPLE_MODERN_COMPAT_GROUPS_H
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/*
 * w14-compatsweep.  One declared, DEFAULT-OFF board option, "adt-compat-restore",
 * that puts back the byte-exact stock "compatible" property on named GROUPS of
 * ADT nodes the served Darwin-derived tree strips it from.
 *
 * WHY: measured (w12-dcp tools/match_gap.py, reproduced byte-identically here)
 * the served tree keeps a "compatible" on only 4 of its 451 nodes, and that one
 * stripped property costs 256 IOKit personality/node matches over 248 nodes and
 * 89 driver classes - every single lost match is lost from "compatible", none
 * from "name", "device_type" or "model".  Restoring it has twice been the
 * unlock: once for the three DARTs (w12-dcp) and once for the whole DCP chain.
 * This option is the systematic form of that one fix.
 *
 * WHAT IS ATTESTED: every "compatible" value is copied out of the pinned stock
 * tree runtime/darwin-reference-27/dtree.stock (sha256
 * 0a29c3adc1b8621150445e7082630ac221b76a7a168cbff8a3e1f0d5c72992d0) by
 * evidence/features-20261009/w14-compatsweep/tools/gen_groups.py, which
 * generates modern-compat-groups.c and refuses to emit anything unless each
 * node exists exactly once in both trees, carries the property in the stock
 * tree, and does NOT carry it in the served tree.  No string here was typed by
 * hand and nothing is removed from the tree.
 *
 * WHAT IS DECLARED: the "dart-id" values.  SPTM's t8110dart_bootstrap_instance
 * panics "error -1 getting dart-id" for a restored dart,t8110 node without one
 * (attested, measured by w7-disp0), and the loader's own adt-dart-ids generator
 * cannot help because it keys on the INPUT tree, which has no DART at all.  So
 * a group that restores a dart,t8110 compatible serves its own id.  Only
 * uniqueness is required; iBoot's own numbering is NOT measured.  disp0-probe's
 * dcp-chain and dcp-mapper profiles own 0 and 1, so these start at 2.
 *
 * WHAT IS NOT CLAIMED: that a restored match is an improvement.  A driver that
 * attaches and then blocks, or touches a register this board does not model, is
 * a REGRESSION.  Both directions are measured per group in the evidence README.
 *
 * SCOPE: /arm-io/dcp, /arm-io/dcp/iop-dcp-nub, /arm-io/disp0, /arm-io/dcp0-expert
 * and the dart-dcp / dart-disp0 mapper nodes belong to disp0-probe and to the
 * W-12 endpoint continuation; the generator refuses any group that names them,
 * so the two options can never collide on a (path, name) pair.
 */

typedef struct AppleModernCompatGroup {
    const char *name;
    const AppleModernAdtOverride *rows;
    size_t row_count;
    const char *purpose;
} AppleModernCompatGroup;

extern const AppleModernCompatGroup apple_modern_compat_groups[];
extern const size_t apple_modern_compat_group_count;

/* The group with this exact name, or NULL. */
const AppleModernCompatGroup *apple_modern_compat_group(const char *name);

/*
 * Resolve a '+'-separated group list ("hid-mtp+gpio") into overrides appended
 * to `out` at `*count`, which must have room for `capacity` entries.
 *
 * Returns false and sets errp, having appended nothing, when a name is empty or
 * unknown, when a group is named twice, or when the result would not fit.  The
 * groups are node-disjoint by construction (the generator proves it and
 * test-apple-modern-compat-groups re-checks it), so a successful resolve can
 * never contain a duplicate (path, name) pair.
 */
bool apple_modern_compat_groups_resolve(const char *list,
                                        AppleModernAdtOverride *out,
                                        size_t *count, size_t capacity,
                                        Error **errp);

/* True when any named group restores a "dart,t8110" compatible, and therefore
 * serves its own declared dart-id; such a list cannot be combined with the
 * loader's adt-dart-ids generator. */
bool apple_modern_compat_groups_supply_dart_id(const char *list);

/* Comma-separated list of every group name, for an error message. Static buffer. */
const char *apple_modern_compat_group_names(void);

#endif
