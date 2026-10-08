/* Shared optional /arm-io/mcc property oracle for the AMCC DSID, SLC and DCS
 * performance plan builders (v4). Test-only; included by the core tests.
 *
 * v4: rejections are matched exactly. A present property whose size is not 4
 * gives "<device>: MCC <name> has <n> bytes, expected 4" (checked before the
 * value, so a wrong size never reports a value); a 4-byte value the model does
 * not mirror gives "<device>: MCC <name>=<value> is not modelled". <device> is
 * the builder's prefix, which each test stores in opt_device before sweeping
 * ("DCS performance", "MCC DSID" or "MCC SLC").
 *
 * The matched trees carry none of amcc-plane-enable-mask, max-way-count or
 * dcs-channel-enable-mask. A test tree is made from a private copy by
 * renaming an existing /arm-io/mcc property that no plan builder validates
 * (the ADT name is a fixed 32-byte field, so an in-place rename keeps the
 * serialization valid) and storing the value under test in its data. Wrong
 * sizes 1..3 rewrite only the length field (the padded extent is unchanged),
 * size 8 renames the 8-byte dramcfg-data, and size 0 rebuilds the copy with
 * the 4 data bytes removed.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef TEST_APPLE_MODERN_MCC_OPTIONAL_PROPS_H
#define TEST_APPLE_MODERN_MCC_OPTIONAL_PROPS_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 4-byte /arm-io/mcc properties that no plan builder reads (each test proves
 * it by removing the donor under a neutral name and planning again). */
#define OPT_DONOR_A "dsid_mgmt"
#define OPT_DONOR_B "mcw-reg-idx"
#define OPT_DONOR_C "pmp_ptd_db_reg_idx"
#define OPT_DONOR_WIDE "dramcfg-data"   /* 8 bytes, not read by any builder */

typedef bool (*OptPlanFn)(AppleModernBlob tree, void *plan, Error **errp);

typedef struct OptTree {
    uint8_t *data;
    size_t size;
} OptTree;

static OptTree opt_copy(const uint8_t *tree, size_t size)
{
    OptTree copy = {malloc(size), size};
    CHECK(copy.data);
    memcpy(copy.data, tree, size);
    return copy;
}

/* Header (32-byte name + 32-bit flags) of an /arm-io/mcc property in a copy. */
static uint8_t *opt_header(OptTree *copy, const char *name, uint32_t *length)
{
    AppleModernBlob blob = {copy->data, copy->size}, property;
    Error *error = NULL;
    CHECK(apple_modern_adt_property(blob, "/arm-io/mcc", name, &property, &error));
    CHECK(!error);
    uint8_t *header = (uint8_t *)property.data - 36;
    CHECK(header >= copy->data && !strcmp((const char *)header, name));
    uint32_t flags;
    memcpy(&flags, header + 32, 4);
    CHECK((flags & 0x7fffffffU) == property.size);
    if (length) {
        *length = property.size;
    }
    return header;
}

static void opt_rename(OptTree *copy, const char *from, const char *to)
{
    uint8_t *header = opt_header(copy, from, NULL);
    CHECK(strlen(to) < 32);
    memset(header, 0, 32);
    memcpy(header, to, strlen(to));
}

/* Rename a 4-byte donor to `name` and store `value` (little endian). */
static void opt_set(OptTree *copy, const char *donor, const char *name, uint32_t value)
{
    uint32_t length;
    uint8_t *header = opt_header(copy, donor, &length);
    CHECK(length == 4);
    opt_rename(copy, donor, name);
    for (unsigned i = 0; i < 4; i++) {
        header[36 + i] = (uint8_t)(value >> (8 * i));
    }
}

/* Rename a 4-byte donor and give it 1..3 bytes (padding is unchanged). */
static void opt_set_short(OptTree *copy, const char *donor, const char *name,
                          uint32_t value, uint32_t size)
{
    CHECK(size >= 1 && size <= 3);
    opt_set(copy, donor, name, value);
    uint8_t *header = opt_header(copy, name, NULL);
    uint32_t flags;
    memcpy(&flags, header + 32, 4);
    flags = (flags & 0x80000000U) | size;
    memcpy(header + 32, &flags, 4);
    uint32_t check;
    opt_header(copy, name, &check);
    CHECK(check == size);
}

/* Rename a 4-byte donor and drop its data: the copy shrinks by 4 bytes. */
static void opt_set_empty(OptTree *copy, const char *donor, const char *name)
{
    uint32_t length;
    uint8_t *header = opt_header(copy, donor, &length);
    CHECK(length == 4);
    opt_rename(copy, donor, name);
    size_t data = (size_t)(header + 36 - copy->data);
    memmove(copy->data + data, copy->data + data + 4, copy->size - data - 4);
    copy->size -= 4;
    uint32_t flags;
    memcpy(&flags, header + 32, 4);
    flags &= 0x80000000U;
    memcpy(header + 32, &flags, 4);
    uint32_t check;
    opt_header(copy, name, &check);
    CHECK(check == 0);
}

/* Rename the 8-byte dramcfg-data and store a 64-bit value. */
static void opt_set_wide(OptTree *copy, const char *name, uint64_t value)
{
    uint32_t length;
    uint8_t *header = opt_header(copy, OPT_DONOR_WIDE, &length);
    CHECK(length == 8);
    opt_rename(copy, OPT_DONOR_WIDE, name);
    for (unsigned i = 0; i < 8; i++) {
        header[36 + i] = (uint8_t)(value >> (8 * i));
    }
}

static bool opt_all_zero(const void *plan, size_t size)
{
    const uint8_t *bytes = plan;
    for (size_t i = 0; i < size; i++) {
        if (bytes[i]) {
            return false;
        }
    }
    return true;
}

static unsigned opt_accepts, opt_rejects, opt_size_rejects;
static const char *opt_device;   /* builder prefix of the test that includes this */

/* Plan on the copy and require rejection with exactly `want`, the output
 * left zeroed, and a NULL errp tolerated. */
static void opt_reject_exact(OptTree *copy, OptPlanFn build, void *plan, size_t plan_size,
                             const char *want)
{
    AppleModernBlob blob = {copy->data, copy->size};
    Error *error = NULL;
    memset(plan, 0x5a, plan_size);
    CHECK(!build(blob, plan, &error));
    CHECK(error != NULL);
    if (strcmp(error->message, want)) {
        fprintf(stderr, "unexpected optional-property error: \"%s\", expected \"%s\"\n",
                error->message, want);
    }
    CHECK(!strcmp(error->message, want));
    error_free(error);
    CHECK(opt_all_zero(plan, plan_size));
    memset(plan, 0x5a, plan_size);
    CHECK(!build(blob, plan, NULL));
    CHECK(opt_all_zero(plan, plan_size));
}

/* Plan on the copy: accepted with exactly `expected`, or rejected with exactly
 * "<opt_device>: MCC <rejected_name><rejected_value>is not modelled", where
 * rejected_value is "=<%#x> " (the trailing space ends the value). */
static void opt_expect(OptTree *copy, OptPlanFn build, void *plan, size_t plan_size,
                       const void *expected, const char *rejected_name,
                       const char *rejected_value)
{
    AppleModernBlob blob = {copy->data, copy->size};
    Error *error = NULL;
    char want[160];
    if (!rejected_name) {
        memset(plan, 0x5a, plan_size);
        CHECK(build(blob, plan, &error));
        CHECK(!error && !memcmp(plan, expected, plan_size));
        opt_accepts++;
        return;
    }
    CHECK(opt_device && rejected_value && rejected_value[0] == '=' &&
          rejected_value[strlen(rejected_value) - 1] == ' ');
    CHECK(snprintf(want, sizeof(want), "%s: MCC %s%sis not modelled", opt_device,
                   rejected_name, rejected_value) < (int)sizeof(want));
    opt_reject_exact(copy, build, plan, plan_size, want);
    opt_rejects++;
}

/* A present property of `size` != 4 bytes: rejected with exactly
 * "<opt_device>: MCC <name> has <size> bytes, expected 4". */
static void opt_expect_size(OptTree *copy, OptPlanFn build, void *plan, size_t plan_size,
                            const char *name, uint32_t size)
{
    char want[160];
    CHECK(opt_device && size != 4);
    uint32_t stored;
    opt_header(copy, name, &stored);
    CHECK(stored == size);
    CHECK(snprintf(want, sizeof(want), "%s: MCC %s has %u bytes, expected 4", opt_device,
                   name, (unsigned)size) < (int)sizeof(want));
    opt_reject_exact(copy, build, plan, plan_size, want);
    opt_rejects++;
    opt_size_rejects++;
}

static const uint32_t opt_mask_rejected[] = {
    0, 1, 2, 4, 8, 0x3, 0x7, 0xb, 0xd, 0xe, 0x10, 0x1f, 0xf0, 0xff, 0x10f,
    0x8000000fU, 0xfffffff0U, 0xffffffffU,
};
static const uint32_t opt_ways_accepted[] = {0, 1, 0xc, 0x7e, 0x7f};
static const uint32_t opt_ways_rejected[] = {
    0x80, 0x81, 0xff, 0x100, 0x17f, 0x8000000cU, 0x8000007fU, 0xffffffffU,
};

/* One validated property: `exact` properties accept only `limit`; others
 * accept 0..limit. Also wrong sizes 0, 1, 2, 3 and 8 with the default value
 * in the leading bytes, and donor removal (proves the donor is unvalidated). */
static void opt_property_sweep(const uint8_t *tree, size_t size, const char *name,
                               bool exact, uint32_t limit, OptPlanFn build,
                               void *plan, size_t plan_size, const void *expected)
{
    char text[32];
    OptTree copy = opt_copy(tree, size);
    opt_rename(&copy, OPT_DONOR_A, "zz-opt-unvalidated");
    opt_expect(&copy, build, plan, plan_size, expected, NULL, NULL);
    free(copy.data);
    copy = opt_copy(tree, size);
    opt_set(&copy, OPT_DONOR_A, name, limit);
    opt_expect(&copy, build, plan, plan_size, expected, NULL, NULL);
    free(copy.data);
    if (exact) {
        for (size_t i = 0; i < sizeof(opt_mask_rejected) / sizeof(opt_mask_rejected[0]); i++) {
            copy = opt_copy(tree, size);
            opt_set(&copy, OPT_DONOR_A, name, opt_mask_rejected[i]);
            snprintf(text, sizeof(text), "=%#x ", opt_mask_rejected[i]);
            opt_expect(&copy, build, plan, plan_size, expected, name,
                       opt_mask_rejected[i] ? text : "=0 ");
            free(copy.data);
        }
    } else {
        for (size_t i = 0; i < sizeof(opt_ways_accepted) / sizeof(opt_ways_accepted[0]); i++) {
            copy = opt_copy(tree, size);
            opt_set(&copy, OPT_DONOR_A, name, opt_ways_accepted[i]);
            opt_expect(&copy, build, plan, plan_size, expected, NULL, NULL);
            free(copy.data);
        }
        for (size_t i = 0; i < sizeof(opt_ways_rejected) / sizeof(opt_ways_rejected[0]); i++) {
            copy = opt_copy(tree, size);
            opt_set(&copy, OPT_DONOR_A, name, opt_ways_rejected[i]);
            snprintf(text, sizeof(text), "=%#x ", opt_ways_rejected[i]);
            opt_expect(&copy, build, plan, plan_size, expected, name, text);
            free(copy.data);
        }
    }
    /* Wrong sizes are rejected with the size message even when the leading
     * bytes hold an accepted value, and (v4) also when they hold a rejected
     * one: the size is checked before the value. */
    const uint32_t bad = exact ? 0 : opt_ways_rejected[0];
    for (uint32_t bytes = 1; bytes <= 3; bytes++) {
        copy = opt_copy(tree, size);
        opt_set_short(&copy, OPT_DONOR_A, name, limit, bytes);
        opt_expect_size(&copy, build, plan, plan_size, name, bytes);
        free(copy.data);
        copy = opt_copy(tree, size);
        opt_set_short(&copy, OPT_DONOR_A, name, bad, bytes);
        opt_expect_size(&copy, build, plan, plan_size, name, bytes);
        free(copy.data);
    }
    copy = opt_copy(tree, size);
    opt_set_empty(&copy, OPT_DONOR_A, name);
    opt_expect_size(&copy, build, plan, plan_size, name, 0);
    free(copy.data);
    copy = opt_copy(tree, size);
    opt_set_wide(&copy, name, limit);
    opt_expect_size(&copy, build, plan, plan_size, name, 8);
    free(copy.data);
    copy = opt_copy(tree, size);
    opt_set_wide(&copy, name, ((uint64_t)limit << 32) | bad);
    opt_expect_size(&copy, build, plan, plan_size, name, 8);
    free(copy.data);
}

/* A property this builder does not validate: any value or size is accepted. */
static void opt_ignored_sweep(const uint8_t *tree, size_t size, const char *name,
                              OptPlanFn build, void *plan, size_t plan_size,
                              const void *expected)
{
    static const uint32_t values[] = {0, 0x7, 0xf, 0x80, 0xffffffffU};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        OptTree copy = opt_copy(tree, size);
        opt_set(&copy, OPT_DONOR_B, name, values[i]);
        opt_expect(&copy, build, plan, plan_size, expected, NULL, NULL);
        free(copy.data);
    }
    OptTree copy = opt_copy(tree, size);
    opt_set_wide(&copy, name, UINT64_MAX);
    opt_expect(&copy, build, plan, plan_size, expected, NULL, NULL);
    free(copy.data);
}
#endif
