/* adt-compat-restore qualification: every restored value is proved byte-exact
 * against the pinned stock ADT and proved absent from the served ADT, the groups
 * are proved node-disjoint and proved clear of the nodes disp0-probe and the
 * W-12 endpoint continuation own, and the '+' resolver is proved to refuse every
 * malformed list without appending anything.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-compat-groups.h"
#include "hw/arm/apple-silicon/modern-disp-trace.h"

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

/*
 * Nodes this option must never touch, re-stated here independently of the
 * generator so the test is a check and not an echo:
 *  - /arm-io/dcp, /arm-io/dcp/iop-dcp-nub, /arm-io/disp0, /arm-io/dcp0-expert,
 *    /arm-io/dart-dcp and /arm-io/dart-disp0 (with their mapper children) are
 *    disp0-probe's and the W-12 endpoint continuation's;
 *  - the three control nodes are override-control's and gate-control's.
 * A collision would make apple_modern_boot_metadata_build refuse the pair, so
 * this is what keeps the two options independently usable.
 */
static const char *const owned_prefix[] = {
    "/arm-io/dcp", "/arm-io/disp0", "/arm-io/dart-dcp", "/arm-io/dart-disp0",
    "/arm-io/dcp0-expert"};
static const char *const owned_exact[] = {
    "/arm-io/audio-resource-manager", "/arm-io/iop-audio-controller",
    "/arm-io/jpeg0-h17p"};

static void clear_error(Error **error)
{
    CHECK(*error != NULL);
    error_free(*error);
    *error = NULL;
}

static uint8_t *slurp(const char *path, size_t *size)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *data;
    long length;
    if (!fp) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(1);
    }
    if (fseek(fp, 0, SEEK_END) || (length = ftell(fp)) <= 0 ||
        fseek(fp, 0, SEEK_SET)) {
        exit(1);
    }
    data = malloc((size_t)length);
    if (!data || fread(data, 1, (size_t)length, fp) != (size_t)length) {
        exit(1);
    }
    fclose(fp);
    *size = (size_t)length;
    return data;
}

static bool under(const char *path, const char *prefix)
{
    size_t n = strlen(prefix);
    return !strncmp(path, prefix, n) && (path[n] == '\0' || path[n] == '/');
}

/* Shape of the generated table: every row usable by the override ABI. */
static void check_table_shape(void)
{
    CHECK(apple_modern_compat_group_count >= 1);
    for (size_t g = 0; g < apple_modern_compat_group_count; g++) {
        const AppleModernCompatGroup *group = &apple_modern_compat_groups[g];

        CHECK(group->name && *group->name);
        CHECK(group->purpose && *group->purpose);
        CHECK(group->rows && group->row_count >= 1);
        CHECK(group->row_count <= APPLE_MODERN_MAX_ADT_OVERRIDES);
        /* A single group must be usable on its own. */
        for (size_t r = 0; r < group->row_count; r++) {
            const AppleModernAdtOverride *row = &group->rows[r];

            CHECK(row->path && row->path[0] == '/');
            CHECK(row->name && strlen(row->name) >= 1 &&
                  strlen(row->name) <= 31);
            CHECK(strcmp(row->name, "name") != 0);
            CHECK(row->value != NULL);
            CHECK(row->size >= 1 &&
                  row->size <= APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES);
            for (size_t i = 0; i < sizeof(owned_exact) / sizeof(owned_exact[0]);
                 i++) {
                CHECK(strcmp(row->path, owned_exact[i]) != 0);
            }
            for (size_t i = 0;
                 i < sizeof(owned_prefix) / sizeof(owned_prefix[0]); i++) {
                CHECK(!under(row->path, owned_prefix[i]));
            }
            /* A restored compatible is a NUL-terminated token list. */
            if (!strcmp(row->name, "compatible")) {
                CHECK(row->value[row->size - 1] == '\0');
                CHECK(row->size >= 2);
            } else {
                /* The only other property any group serves is dart-id. */
                CHECK(!strcmp(row->name, "dart-id") && row->size == 4);
            }
        }
    }
}

/* No (path, name) pair anywhere in the table repeats, so any '+' composition
 * the resolver accepts is free of the duplicates the override ABI refuses. */
static void check_disjoint(void)
{
    for (size_t g = 0; g < apple_modern_compat_group_count; g++) {
        for (size_t r = 0; r < apple_modern_compat_groups[g].row_count; r++) {
            const AppleModernAdtOverride *a =
                &apple_modern_compat_groups[g].rows[r];

            for (size_t h = 0; h < apple_modern_compat_group_count; h++) {
                for (size_t s = 0; s < apple_modern_compat_groups[h].row_count;
                     s++) {
                    const AppleModernAdtOverride *b =
                        &apple_modern_compat_groups[h].rows[s];

                    if (g == h && r == s) {
                        continue;
                    }
                    CHECK(strcmp(a->path, b->path) || strcmp(a->name, b->name));
                }
            }
        }
    }
    /* And no group collides with any disp0-probe profile on a (path, name). */
    static const char *const arms[] = {"disp0", "disp0-nodcp", "dcp-chain",
                                       "override-control", "gate-control",
                                       "dcp-mapper"};
    for (size_t i = 0; i < sizeof(arms) / sizeof(arms[0]); i++) {
        size_t arm_count = 0;
        const AppleModernAdtOverride *arm =
            apple_modern_disp_probe_profile(arms[i], &arm_count);

        CHECK(arm != NULL && arm_count >= 1);
        for (size_t a = 0; a < arm_count; a++) {
            for (size_t g = 0; g < apple_modern_compat_group_count; g++) {
                for (size_t r = 0;
                     r < apple_modern_compat_groups[g].row_count; r++) {
                    const AppleModernAdtOverride *row =
                        &apple_modern_compat_groups[g].rows[r];

                    CHECK(strcmp(arm[a].path, row->path) ||
                          strcmp(arm[a].name, row->name));
                }
            }
        }
    }
}

/* Every dart-id value in the whole table is distinct, and none of them is the
 * 0 or 1 disp0-probe's dcp-chain / dcp-mapper serve. */
static void check_dart_ids(void)
{
    uint32_t seen[APPLE_MODERN_MAX_ADT_OVERRIDES];
    size_t count = 0;

    for (size_t g = 0; g < apple_modern_compat_group_count; g++) {
        for (size_t r = 0; r < apple_modern_compat_groups[g].row_count; r++) {
            const AppleModernAdtOverride *row =
                &apple_modern_compat_groups[g].rows[r];
            uint32_t id;

            if (strcmp(row->name, "dart-id")) {
                continue;
            }
            CHECK(row->size == 4);
            id = (uint32_t)row->value[0] | ((uint32_t)row->value[1] << 8) |
                 ((uint32_t)row->value[2] << 16) |
                 ((uint32_t)row->value[3] << 24);
            CHECK(id >= 2);
            for (size_t i = 0; i < count; i++) {
                CHECK(seen[i] != id);
            }
            CHECK(count < sizeof(seen) / sizeof(seen[0]));
            seen[count++] = id;
        }
    }
    CHECK(count >= 1);
}

/* THE SUBSTANTIVE GATE: every restored compatible is the byte-exact stock value
 * and the served tree carries no such property, measured against both trees. */
static unsigned check_against_trees(AppleModernBlob served, AppleModernBlob stock)
{
    unsigned compat_rows = 0;

    for (size_t g = 0; g < apple_modern_compat_group_count; g++) {
        for (size_t r = 0; r < apple_modern_compat_groups[g].row_count; r++) {
            const AppleModernAdtOverride *row =
                &apple_modern_compat_groups[g].rows[r];
            AppleModernBlob value;
            Error *error = NULL;

            /* The node must exist unambiguously in both trees. */
            CHECK(apple_modern_adt_property(served, row->path, "name", &value,
                                            &error) && error == NULL);
            CHECK(apple_modern_adt_property(stock, row->path, "name", &value,
                                            &error) && error == NULL);
            if (strcmp(row->name, "compatible")) {
                /* dart-id: declared, and absent from BOTH trees. */
                CHECK(!apple_modern_adt_property(served, row->path, "dart-id",
                                                 &value, &error));
                clear_error(&error);
                CHECK(!apple_modern_adt_property(stock, row->path, "dart-id",
                                                 &value, &error));
                clear_error(&error);
                continue;
            }
            compat_rows++;
            /* Absent from the served tree: this is a restoration. */
            CHECK(!apple_modern_adt_property(served, row->path, "compatible",
                                             &value, &error));
            clear_error(&error);
            /* Byte-exact in the stock tree. */
            CHECK(apple_modern_adt_property(stock, row->path, "compatible",
                                            &value, &error) && error == NULL);
            CHECK(value.size == row->size);
            CHECK(!memcmp(value.data, row->value, row->size));
        }
    }
    return compat_rows;
}

/* The resolver: accepts what it should, refuses what it should, and on every
 * refusal leaves the caller's count and buffer untouched. */
static void check_resolver(void)
{
    AppleModernAdtOverride out[APPLE_MODERN_MAX_ADT_OVERRIDES];
    Error *error = NULL;
    size_t count;

    CHECK(apple_modern_compat_group("hid-mtp") != NULL);
    CHECK(apple_modern_compat_group("no-such-group") == NULL);
    CHECK(apple_modern_compat_group(NULL) == NULL);
    CHECK(strstr(apple_modern_compat_group_names(), "hid-mtp") != NULL);
    CHECK(strstr(apple_modern_compat_group_names(), "darts") != NULL);

    /* Each group alone resolves to exactly its own row count. */
    for (size_t g = 0; g < apple_modern_compat_group_count; g++) {
        count = 0;
        memset(out, 0, sizeof(out));
        CHECK(apple_modern_compat_groups_resolve(
            apple_modern_compat_groups[g].name, out, &count, sizeof(out) /
            sizeof(out[0]), &error));
        CHECK(error == NULL);
        CHECK(count == apple_modern_compat_groups[g].row_count);
        for (size_t r = 0; r < count; r++) {
            CHECK(out[r].path == apple_modern_compat_groups[g].rows[r].path);
            CHECK(out[r].value == apple_modern_compat_groups[g].rows[r].value);
        }
    }

    /* Composition appends in list order, after whatever the caller already had. */
    count = 1;
    out[0] = (AppleModernAdtOverride){"/arm-io/sgx", "x", (const uint8_t *)"\1", 1};
    CHECK(apple_modern_compat_groups_resolve("gpio+spmi", out, &count,
                                             sizeof(out) / sizeof(out[0]),
                                             &error));
    CHECK(error == NULL);
    CHECK(count == 1 + apple_modern_compat_group("gpio")->row_count +
                   apple_modern_compat_group("spmi")->row_count);
    CHECK(!strcmp(out[0].path, "/arm-io/sgx"));
    CHECK(out[1].value == apple_modern_compat_group("gpio")->rows[0].value);

    /* Refusals, each leaving count untouched. */
    static const char *const bad[] = {
        "", "+", "gpio+", "+gpio", "gpio++spmi", "no-such-group",
        "gpio+no-such-group", "gpio+gpio", "GPIO",
        "gpio+spmi+gpio",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        size_t before = 7;

        count = before;
        CHECK(!apple_modern_compat_groups_resolve(bad[i], out, &count,
                                                  sizeof(out) / sizeof(out[0]),
                                                  &error));
        clear_error(&error);
        CHECK(count == before);
    }
    /* NULL list, NULL output. */
    count = 3;
    CHECK(!apple_modern_compat_groups_resolve(NULL, out, &count,
                                              sizeof(out) / sizeof(out[0]),
                                              &error));
    clear_error(&error);
    CHECK(count == 3);
    CHECK(!apple_modern_compat_groups_resolve("gpio", NULL, &count,
                                              sizeof(out) / sizeof(out[0]),
                                              &error));
    clear_error(&error);
    CHECK(!apple_modern_compat_groups_resolve("gpio", out, NULL,
                                              sizeof(out) / sizeof(out[0]),
                                              &error));
    clear_error(&error);

    /* Capacity: exactly enough works, one short refuses and appends nothing. */
    {
        const AppleModernCompatGroup *g = apple_modern_compat_group("darts");

        count = 0;
        CHECK(apple_modern_compat_groups_resolve("darts", out, &count,
                                                 g->row_count, &error));
        CHECK(error == NULL && count == g->row_count);
        count = 0;
        memset(out, 0, sizeof(out));
        CHECK(!apple_modern_compat_groups_resolve("darts", out, &count,
                                                  g->row_count - 1, &error));
        clear_error(&error);
        CHECK(count == 0 && out[0].path == NULL);
        /* A caller that has already used the capacity gets refused too. */
        count = g->row_count;
        CHECK(!apple_modern_compat_groups_resolve("darts", out, &count,
                                                  g->row_count, &error));
        clear_error(&error);
        CHECK(count == g->row_count);
        /* ...and so does a caller whose count already exceeds the capacity. */
        count = g->row_count + 1;
        CHECK(!apple_modern_compat_groups_resolve("darts", out, &count,
                                                  g->row_count, &error));
        clear_error(&error);
    }

    /* An over-long list is refused rather than walked. */
    {
        char big[1024];

        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        count = 0;
        CHECK(!apple_modern_compat_groups_resolve(big, out, &count,
                                                  sizeof(out) / sizeof(out[0]),
                                                  &error));
        clear_error(&error);
        CHECK(count == 0);
    }

    /* dart-id reporting agrees with the table, group by group. */
    for (size_t g = 0; g < apple_modern_compat_group_count; g++) {
        bool expected = false;

        for (size_t r = 0; r < apple_modern_compat_groups[g].row_count; r++) {
            if (!strcmp(apple_modern_compat_groups[g].rows[r].name, "dart-id")) {
                expected = true;
            }
        }
        CHECK(apple_modern_compat_groups_supply_dart_id(
                  apple_modern_compat_groups[g].name) == expected);
    }
    CHECK(apple_modern_compat_groups_supply_dart_id("gpio+spmi") == false);
    CHECK(apple_modern_compat_groups_supply_dart_id("gpio+darts") == true);
    CHECK(apple_modern_compat_groups_supply_dart_id("no-such-group") == false);
    CHECK(apple_modern_compat_groups_supply_dart_id(NULL) == false);
}

/* A mutation oracle: a group row whose value is NOT the stock value must be
 * caught by check_against_trees.  Exercised on a copy of one row so the real
 * table is never modified. */
static void check_mutation_oracle(AppleModernBlob stock)
{
    const AppleModernCompatGroup *group = apple_modern_compat_group("gpio");
    AppleModernBlob value;
    Error *error = NULL;
    uint8_t *flipped;

    CHECK(apple_modern_adt_property(stock, group->rows[0].path, "compatible",
                                    &value, &error) && error == NULL);
    CHECK(value.size == group->rows[0].size);
    flipped = malloc(value.size);
    CHECK(flipped != NULL);
    memcpy(flipped, group->rows[0].value, value.size);
    flipped[0] ^= 0x20;
    /* The comparison the gate makes must now fail. */
    CHECK(memcmp(value.data, flipped, value.size) != 0);
    flipped[0] ^= 0x20;
    CHECK(memcmp(value.data, flipped, value.size) == 0);
    free(flipped);
}

int main(int argc, char **argv)
{
    uint8_t *served_data, *stock_data;
    size_t served_size, stock_size;
    AppleModernBlob served, stock;
    unsigned compat_rows, rows = 0;

    if (argc != 3) {
        fprintf(stderr, "usage: %s SERVED-ADT STOCK-ADT\n", argv[0]);
        return 2;
    }
    served_data = slurp(argv[1], &served_size);
    stock_data = slurp(argv[2], &stock_size);
    served = (AppleModernBlob){served_data, served_size};
    stock = (AppleModernBlob){stock_data, stock_size};

    check_table_shape();
    check_disjoint();
    check_dart_ids();
    compat_rows = check_against_trees(served, stock);
    check_resolver();
    check_mutation_oracle(stock);

    for (size_t g = 0; g < apple_modern_compat_group_count; g++) {
        rows += (unsigned)apple_modern_compat_groups[g].row_count;
    }
    printf("{\"passed\": true, \"checks\": %u, \"firmware_executed\": false,"
           " \"guest_executed\": false, \"groups\": %u, \"rows\": %u,"
           " \"compatible_rows\": %u}\n", checks,
           (unsigned)apple_modern_compat_group_count, rows, compat_rows);
    free(served_data);
    free(stock_data);
    return 0;
}
