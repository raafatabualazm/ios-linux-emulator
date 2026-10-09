/* Declared /arm-io clock/power gate escape hatches (pmgr-ungate).
 * Production-source test, no guest launch, no guest writes.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *   -fsanitize=address,undefined hw/arm/apple-silicon/modern-boot-layout.c \
 *   hw/arm/apple-silicon/modern-boot-metadata.c \
 *   hw/arm/apple-silicon/modern-pmgr-ungate.c \
 *   scripts/test-apple-modern-pmgr-ungate.c -o /tmp/test-pmgr-ungate \
 *   && /tmp/test-pmgr-ungate [components-dir]
 */
#define METADATA_REGRESSION_MAIN metadata_regression_main
#include "test-apple-modern-boot-metadata.c"
#include "hw/arm/apple-silicon/modern-pmgr-ungate.h"

static unsigned ungate_checks;

#define UCHECK(c) do { ungate_checks++; if (!(c)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

static uint32_t rd32u(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

/* Independent bounded ADT walk, sharing no code with the serializer: counts
 * nodes/properties and enumerates one node's property names and values. */
typedef struct UWalk {
    const uint8_t *data;
    size_t size, cursor;
    unsigned nodes, props;
    const char *want_path;
    char names[512][32];
    const uint8_t *values[512];
    uint32_t lengths[512];
    unsigned want_count, want_seen;
} UWalk;

static void uwalk_node(UWalk *w, const char *parent, unsigned depth)
{
    uint32_t count, children;
    char name[128] = "", path[512];
    size_t begin;

    UCHECK(depth < 16 && w->cursor + 8 <= w->size);
    count = rd32u(w->data + w->cursor);
    children = rd32u(w->data + w->cursor + 4);
    w->cursor += 8;
    begin = w->cursor;
    w->nodes++;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p = w->data + w->cursor;
        uint32_t length;
        UCHECK(w->cursor + 36 <= w->size);
        length = rd32u(p + 32) & 0x7fffffff;
        w->cursor += 36;
        UCHECK(w->cursor + ((length + 3) & ~3U) <= w->size);
        if (!strcmp((const char *)p, "name")) {
            snprintf(name, sizeof(name), "%s",
                     (const char *)w->data + w->cursor);
        }
        w->cursor += (length + 3) & ~3U;
        w->props++;
    }
    if (!depth) {
        snprintf(path, sizeof(path), "/");
    } else if (depth == 1) {
        snprintf(path, sizeof(path), "/%s", name);
    } else {
        snprintf(path, sizeof(path), "%s/%s", parent, name);
    }
    if (w->want_path && !strcmp(path, w->want_path)) {
        size_t c = begin;
        w->want_seen++;
        for (uint32_t i = 0; i < count; i++) {
            const uint8_t *p = w->data + c;
            uint32_t length = rd32u(p + 32) & 0x7fffffff;
            UCHECK(w->want_count < 512);
            snprintf(w->names[w->want_count], 32, "%s", (const char *)p);
            w->values[w->want_count] = p + 36;
            w->lengths[w->want_count++] = length;
            c += 36 + ((length + 3) & ~3U);
        }
    }
    for (uint32_t i = 0; i < children; i++) {
        uwalk_node(w, path, depth + 1);
    }
}

static UWalk uwalk(const uint8_t *data, size_t size, const char *want_path)
{
    UWalk w = {.data = data, .size = size, .want_path = want_path};
    uwalk_node(&w, "", 0);
    UCHECK(w.cursor == size);
    return w;
}

static int ufind(const UWalk *w, const char *name)
{
    for (unsigned i = 0; i < w->want_count; i++) {
        if (!strcmp(w->names[i], name)) {
            return (int)i;
        }
    }
    return -1;
}

/* The two names are the exact BootKC strings; a typo would silently restore
 * the gating, so they are pinned here as literals independent of the table. */
static const char *const attested_names[2] = { "no-clock-gate", "no-power-gate" };

static void test_table(void)
{
    size_t count = 123;
    const AppleModernAdtOverride *t = apple_modern_pmgr_ungate_overrides(&count);

    UCHECK(t && count == APPLE_MODERN_PMGR_UNGATE_COUNT && count == 2);
    for (size_t i = 0; i < count; i++) {
        UCHECK(!strcmp(t[i].path, "/arm-io"));
        UCHECK(!strcmp(t[i].name, attested_names[i]));
        UCHECK(t[i].size == 1 && t[i].value && t[i].value[0] != 0);
    }
    UCHECK(strcmp(t[0].name, t[1].name) != 0);
    /* A NULL count argument is accepted and still returns the table. */
    UCHECK(apple_modern_pmgr_ungate_overrides(NULL) == t);
    /* Static storage: the same pointer every call. */
    UCHECK(apple_modern_pmgr_ungate_overrides(&count) == t && count == 2);
}

/* Applies the table to a tree and checks the result exhaustively. */
static void check_applied(AppleModernBootInput *components, const char *label)
{
    size_t count = 0;
    const AppleModernAdtOverride *t = apple_modern_pmgr_ungate_overrides(&count);
    AppleModernBootMetadataInput input = {.components = components,
        .command_line = "-v", .command_line_length = 2, .has_mte = true};
    AppleModernBootMetadataInput bad;
    AppleModernBootMetadata off = {0}, on = {0}, again = {0};
    Error *error = NULL;
    UWalk a, b;
    AppleModernBlob view;
    uint8_t *original = malloc(components->dtree.size);

    UCHECK(original != NULL);
    memcpy(original, components->dtree.data, components->dtree.size);

    UCHECK(apple_modern_boot_metadata_build(&input, &off, &error));
    input.overrides = t;
    input.override_count = count;
    UCHECK(apple_modern_boot_metadata_build(&input, &on, &error));
    UCHECK(!error);

    a = uwalk(off.dtree, off.dtree_size, "/arm-io");
    b = uwalk(on.dtree, on.dtree_size, "/arm-io");
    /* Exactly one /arm-io, so the override can never be ambiguous. */
    UCHECK(a.want_seen == 1 && b.want_seen == 1);
    /* Both properties are new: the stock and served trees carry neither. */
    UCHECK(ufind(&a, "no-clock-gate") < 0 && ufind(&a, "no-power-gate") < 0);
    UCHECK(ufind(&b, "no-clock-gate") >= 0 && ufind(&b, "no-power-gate") >= 0);
    /* Node count unchanged; exactly two properties added, on /arm-io only. */
    UCHECK(a.nodes == b.nodes);
    UCHECK(b.props == a.props + 2);
    UCHECK(b.want_count == a.want_count + 2);
    for (size_t i = 0; i < count; i++) {
        view = prop_view(&on, "/arm-io", t[i].name);
        UCHECK(view.size == 1 && view.data[0] == t[i].value[0]);
    }
    /* Every other /arm-io property is byte-identical to the unpatched tree. */
    for (unsigned i = 0; i < a.want_count; i++) {
        int k = ufind(&b, a.names[i]);
        UCHECK(k >= 0 && b.lengths[k] == a.lengths[i] &&
               !memcmp(b.values[k], a.values[i], a.lengths[i]));
    }
    /* In particular the two function properties the hatches bypass survive,
     * so a tree that has them keeps them and only the lookup is skipped. */
    same_property(components, &on, "/arm-io", "compatible");
    same_property(components, &on, "/arm-io", "name");
    if (ufind(&a, "ranges") >= 0) {
        same_property(components, &on, "/arm-io", "ranges");
    }
    if (ufind(&a, "function-clock_gate") >= 0) {
        same_property(components, &on, "/arm-io", "function-clock_gate");
        same_property(components, &on, "/arm-io", "function-power_gate");
    }
    verify_metadata(&input, &on);
    /* The input tree is never written through. */
    UCHECK(!memcmp(original, components->dtree.data, components->dtree.size));
    /* Deterministic, and a fresh allocation each time. */
    UCHECK(apple_modern_boot_metadata_build(&input, &again, &error));
    UCHECK(again.dtree != on.dtree && again.dtree_size == on.dtree_size &&
           !memcmp(again.dtree, on.dtree, on.dtree_size));
    apple_modern_boot_metadata_clear(&again);

    /* The no-device oracle: the option off must leave the tree alone. With
     * override_count 0 the output is byte-identical to the plain build. */
    bad = input;
    bad.override_count = 0;
    UCHECK(apple_modern_boot_metadata_build(&bad, &again, &error));
    UCHECK(again.dtree_size == off.dtree_size &&
           !memcmp(again.dtree, off.dtree, off.dtree_size));
    apple_modern_boot_metadata_clear(&again);

    /* Applying the table twice is refused rather than duplicating a name. */
    {
        AppleModernAdtOverride twice[4] = {t[0], t[1], t[0], t[1]};
        bad = input;
        bad.overrides = twice;
        bad.override_count = 4;
        rejected_metadata("ungate applied twice", &bad);
    }
    /* A hatch aimed at a loader-owned node is refused. */
    {
        AppleModernAdtOverride owned[1] = {{"/arm-io/aic", t[0].name,
                                            t[0].value, t[0].size}};
        bad = input;
        bad.overrides = owned;
        bad.override_count = 1;
        rejected_metadata("ungate on loader-owned node", &bad);
    }
    /* A zero-length value is refused, which is why presence uses one byte. */
    {
        AppleModernAdtOverride zero[1] = {{t[0].path, t[0].name, t[0].value, 0}};
        bad = input;
        bad.overrides = zero;
        bad.override_count = 1;
        rejected_metadata("ungate zero-length value", &bad);
    }
    /* A misspelled node path is refused, not silently ignored. */
    {
        AppleModernAdtOverride wrong[1] = {{"/arm-io/pmgr-missing", t[0].name,
                                            t[0].value, t[0].size}};
        bad = input;
        bad.overrides = wrong;
        bad.override_count = 1;
        rejected_metadata("ungate node missing", &bad);
    }
    printf("%s: /arm-io properties %u -> %u, tree %zu -> %zu bytes\n", label,
           a.want_count, b.want_count, off.dtree_size, on.dtree_size);
    apple_modern_boot_metadata_clear(&off);
    apple_modern_boot_metadata_clear(&on);
    free(original);
}

static void test_fixture(void)
{
    AppleModernBootInput components = metadata_fixture();
    check_applied(&components, "FIXTURE");
    free_components(&components);
}

static void test_actual_tree(const char *components_dir)
{
    AppleModernBootInput actual = metadata_fixture();
    free_components(&actual);
    actual.bootkc = file(components_dir, "bootkc");
    actual.sptm = file(components_dir, "sptm");
    actual.txm = file(components_dir, "txm");
    actual.dtree = file(components_dir, "dtree");
    actual.trustcache = file(components_dir, "restore-trustcache");
    check_applied(&actual, "ACTUAL");
    free_components(&actual);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_table();
    test_fixture();
    if (argc >= 2) {
        test_actual_tree(argv[1]);
    }
    printf("PASS %u pmgr-ungate checks (+%u shared fixture checks); "
           "no guest writes or execution\n", ungate_checks, checks);
    return 0;
}
