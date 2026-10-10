/* disp0 bind probe qualification: the declared ADT override profiles are
 * anchored byte-for-byte to the stock tree, the logging-aperture plan is
 * derived from the served tree's own reg properties, and the aperture core
 * records without ever failing an access.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-disp-trace.h"

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

#define MAXW APPLE_MODERN_DISP_TRACE_MAX_WINDOWS
#define RECS APPLE_MODERN_DISP_TRACE_RECORDS
#define ARMIO_PARENT UINT64_C(0x210000000)

static const char *const profile_names[] = {
    APPLE_MODERN_DISP_PROBE_DISP0, APPLE_MODERN_DISP_PROBE_NO_DCP,
    APPLE_MODERN_DISP_PROBE_DCP_CHAIN, APPLE_MODERN_DISP_PROBE_CONTROL,
    APPLE_MODERN_DISP_PROBE_GATE_CONTROL, APPLE_MODERN_DISP_PROBE_DCP_MAPPER,
};
#define PROFILES (sizeof(profile_names) / sizeof(profile_names[0]))

/* Properties this project DECLARES rather than restores: they must be absent
 * from the stock tree, otherwise the label would be wrong. */
static int declared_property(const char *name)
{
    return !strcmp(name, "no-dcp-driver") || !strcmp(name, "dart-id");
}

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

static uint64_t little(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

/* ---- the profile tables ------------------------------------------------- */

static void check_profiles(AppleModernBlob served, AppleModernBlob stock)
{
    size_t count = 0;
    unsigned compat_overrides = 0, declared_overrides = 0;

    CHECK(apple_modern_disp_probe_profile(NULL, &count) == NULL);
    CHECK(apple_modern_disp_probe_profile("disp0", NULL) == NULL);
    count = 7;
    CHECK(apple_modern_disp_probe_profile("nonsense", &count) == NULL);
    CHECK(count == 0);
    CHECK(apple_modern_disp_probe_profile("", &count) == NULL);
    CHECK(apple_modern_disp_probe_profile("DISP0", &count) == NULL);

    for (size_t p = 0; p < PROFILES; p++) {
        const AppleModernAdtOverride *profile =
            apple_modern_disp_probe_profile(profile_names[p], &count);
        CHECK(profile != NULL);
        CHECK(count >= 1 && count <= APPLE_MODERN_MAX_ADT_OVERRIDES);
        for (size_t i = 0; i < count; i++) {
            const AppleModernAdtOverride *o = &profile[i];
            AppleModernBlob value = {0};
            Error *error = NULL;
            size_t name_length = strlen(o->name);

            CHECK(o->path && o->name && o->value);
            CHECK(name_length >= 1 && name_length <= 31);
            CHECK(strcmp(o->name, "name") != 0);
            CHECK(o->size >= 1 && o->size <= APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES);
            /* Unique (path, name) inside the profile. */
            for (size_t j = 0; j < i; j++) {
                CHECK(strcmp(o->path, profile[j].path) ||
                      strcmp(o->name, profile[j].name));
            }
            /* The node exists exactly once in the served tree. */
            CHECK(apple_modern_adt_property(served, o->path, "name", &value,
                                            &error));
            CHECK(error == NULL && value.size >= 2);
            if (declared_property(o->name)) {
                declared_overrides++;
                /* Declared, so it must be absent from BOTH trees. */
                CHECK(!apple_modern_adt_property(stock, o->path, o->name,
                                                 &value, &error));
                clear_error(&error);
                CHECK(!apple_modern_adt_property(served, o->path, o->name,
                                                 &value, &error));
                clear_error(&error);
                continue;
            }
            CHECK(!strcmp(o->name, "compatible"));
            compat_overrides++;
            /* Anchored: byte-identical to the stock tree's own value ... */
            CHECK(apple_modern_adt_property(stock, o->path, "compatible",
                                            &value, &error));
            CHECK(error == NULL);
            CHECK(value.size == o->size);
            CHECK(!memcmp(value.data, o->value, o->size));
            CHECK(o->size >= 2 && ((const char *)o->value)[o->size - 1] == '\0');
            /* ... and absent from the served tree, so this is a restoration. */
            CHECK(!apple_modern_adt_property(served, o->path, "compatible",
                                             &value, &error));
            clear_error(&error);
        }
    }
    CHECK(compat_overrides == 21 && declared_overrides == 5);

    CHECK(!apple_modern_disp_probe_supplies_dart_id(
              APPLE_MODERN_DISP_PROBE_DISP0));
    CHECK(!apple_modern_disp_probe_supplies_dart_id(
              APPLE_MODERN_DISP_PROBE_NO_DCP));
    CHECK(!apple_modern_disp_probe_supplies_dart_id(
              APPLE_MODERN_DISP_PROBE_CONTROL));
    CHECK(!apple_modern_disp_probe_supplies_dart_id(
              APPLE_MODERN_DISP_PROBE_GATE_CONTROL));
    CHECK(apple_modern_disp_probe_supplies_dart_id(
              APPLE_MODERN_DISP_PROBE_DCP_CHAIN));
    CHECK(apple_modern_disp_probe_supplies_dart_id(
              APPLE_MODERN_DISP_PROBE_DCP_MAPPER));
    CHECK(!apple_modern_disp_probe_supplies_dart_id("nonsense"));
    CHECK(!apple_modern_disp_probe_supplies_dart_id(NULL));

    /* The dcp-chain arm must restore the whole chain and nothing else. */
    {
        const AppleModernAdtOverride *chain =
            apple_modern_disp_probe_profile(APPLE_MODERN_DISP_PROBE_DCP_CHAIN,
                                            &count);
        static const char *const wanted[] = {
            "/arm-io/disp0", "/arm-io/dcp", "/arm-io/dcp/iop-dcp-nub",
            "/arm-io/dcp0-expert", "/arm-io/dart-dcp", "/arm-io/dart-disp0"};
        CHECK(count == 8);
        for (unsigned w = 0; w < 6; w++) {
            unsigned seen = 0;
            for (size_t i = 0; i < count; i++) {
                seen += !strcmp(chain[i].path, wanted[w]) &&
                        !strcmp(chain[i].name, "compatible");
            }
            CHECK(seen == 1);
        }
    }
    /* The "no-dcp-driver" arm is arm A plus exactly one declared property. */
    {
        const AppleModernAdtOverride *a, *b;
        size_t na = 0, nb = 0;
        a = apple_modern_disp_probe_profile(APPLE_MODERN_DISP_PROBE_DISP0, &na);
        b = apple_modern_disp_probe_profile(APPLE_MODERN_DISP_PROBE_NO_DCP, &nb);
        CHECK(na == 1 && nb == 2);
        CHECK(!strcmp(a[0].path, b[0].path) && !strcmp(a[0].name, b[0].name) &&
              a[0].size == b[0].size && !memcmp(a[0].value, b[0].value, a[0].size));
        CHECK(!strcmp(b[1].name, "no-dcp-driver") && b[1].size == 4);
        CHECK(((const uint8_t *)b[1].value)[0] == 1 &&
              !((const uint8_t *)b[1].value)[1] &&
              !((const uint8_t *)b[1].value)[2] &&
              !((const uint8_t *)b[1].value)[3]);
    }
    /* The control arms must not touch a display node at all. */
    for (size_t p = 0; p < PROFILES; p++) {
        const AppleModernAdtOverride *profile;
        int control = !strcmp(profile_names[p], APPLE_MODERN_DISP_PROBE_CONTROL) ||
                      !strcmp(profile_names[p],
                              APPLE_MODERN_DISP_PROBE_GATE_CONTROL);
        if (!control) {
            continue;
        }
        profile = apple_modern_disp_probe_profile(profile_names[p], &count);
        for (size_t i = 0; i < count; i++) {
            CHECK(strcmp(profile[i].path, "/arm-io/disp0") &&
                  strcmp(profile[i].path, "/arm-io/dcp") &&
                  strcmp(profile[i].path, "/arm-io/dcp0-expert"));
        }
    }
}

/* ---- the aperture plan -------------------------------------------------- */

static unsigned node_window_count(AppleModernBlob tree, unsigned node)
{
    AppleModernBlob reg = {0};
    Error *error = NULL;
    CHECK(apple_modern_adt_property(tree, apple_modern_disp_trace_node_name(node),
                                    "reg", &reg, &error));
    CHECK(error == NULL && reg.size && !(reg.size % 16));
    return (unsigned)(reg.size / 16);
}

static void check_plan(AppleModernBlob served, AppleModernBlob stock)
{
    AppleModernDispTracePlan plan, other;
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    Error *error = NULL;
    const uint64_t dram = UINT64_C(1) << 40, dram_size = UINT64_C(8) << 30;
    unsigned expected = 0, contained = 0;

    CHECK(apple_modern_disp_trace_node_name(APPLE_MODERN_DISP_TRACE_NODES)[0] == '?');
    for (unsigned n = 0; n < APPLE_MODERN_DISP_TRACE_NODES; n++) {
        const char *name = apple_modern_disp_trace_node_name(n);
        CHECK(!strncmp(name, "/arm-io/", 8));
        expected += node_window_count(served, n);
        /* The served tree keeps every reg window the stock tree has. */
        CHECK(node_window_count(stock, n) == node_window_count(served, n));
    }
    CHECK(expected == 29 && expected <= MAXW);

    CHECK(apple_modern_disp_trace_plan_build(served, dram, dram_size, NULL, 0,
                                             &plan, &error));
    CHECK(error == NULL);
    CHECK(plan.count == expected);
    /* 4 of the 29 windows lie inside disp0's own apertures: dcp0-expert
     * reg[2] inside disp0 reg[3], and all three /arm-io/dcp windows inside
     * disp0 reg[4] (0x412800000+0x800000) - attested from the stock reg
     * properties, so the DCP mailbox pages are already covered by disp0's. */
    CHECK(plan.mapped == 25 && expected - plan.mapped == 4);
    for (unsigned i = 0; i < plan.count; i++) {
        const AppleModernDispTraceWindow *w = &plan.windows[i];
        AppleModernBlob reg = {0};
        uint64_t bus, size;
        Error *reg_error = NULL;
        CHECK(w->node < APPLE_MODERN_DISP_TRACE_NODES);
        CHECK(apple_modern_adt_property(served,
                  apple_modern_disp_trace_node_name(w->node), "reg", &reg,
                  &reg_error));
        CHECK(reg_error == NULL);
        CHECK((uint64_t)w->reg_index * 16 + 16 <= reg.size);
        bus = little(reg.data + (size_t)w->reg_index * 16);
        size = little(reg.data + (size_t)w->reg_index * 16 + 8);
        /* /arm-io maps child 0 to parent 0x210000000 (attested, stock tree). */
        CHECK(w->physical_address == bus + ARMIO_PARENT);
        CHECK(w->size == size && w->size);
        CHECK(w->physical_address >= dram + dram_size ||
              w->physical_address + w->size <= dram);
        contained += w->status == APPLE_MODERN_DISP_TRACE_SKIP_CONTAINED;
        CHECK(w->status == APPLE_MODERN_DISP_TRACE_MAPPED ||
              w->status == APPLE_MODERN_DISP_TRACE_SKIP_CONTAINED);
        /* Mapped windows are pairwise disjoint. */
        if (w->status != APPLE_MODERN_DISP_TRACE_MAPPED) {
            continue;
        }
        for (unsigned j = 0; j < i; j++) {
            const AppleModernDispTraceWindow *v = &plan.windows[j];
            if (v->status != APPLE_MODERN_DISP_TRACE_MAPPED) {
                continue;
            }
            CHECK(w->physical_address >= v->physical_address + v->size ||
                  v->physical_address >= w->physical_address + w->size);
        }
    }
    CHECK(contained == 4);
    /* The stock tree has the same reg windows, so the plan must be identical. */
    CHECK(apple_modern_disp_trace_plan_build(stock, dram, dram_size, NULL, 0,
                                             &other, &error));
    CHECK(error == NULL);
    CHECK(other.count == plan.count && other.mapped == plan.mapped);
    CHECK(!memcmp(other.windows, plan.windows, sizeof(plan.windows)));

    /* ---- negative oracles ---- */
    CHECK(!apple_modern_disp_trace_plan_build(served, dram, dram_size, NULL, 0,
                                              NULL, &error));
    clear_error(&error);
    CHECK(!apple_modern_disp_trace_plan_build(served, dram, 0, NULL, 0, &plan,
                                              &error));
    clear_error(&error);
    CHECK(!apple_modern_disp_trace_plan_build(served, 1, UINT64_MAX, NULL, 0,
                                              &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_disp_trace_plan_build(served, dram, dram_size,
              exclusions, APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_disp_trace_plan_build(served, dram, dram_size, NULL, 1,
                                              &plan, &error));
    clear_error(&error);
    /* No ADT at all, and a tree that is only an empty root. */
    {
        static const uint8_t empty[8] = {0};
        AppleModernBlob none = {NULL, 0}, root = {empty, sizeof(empty)};
        CHECK(!apple_modern_disp_trace_plan_build(none, dram, dram_size, NULL, 0,
                                                  &plan, &error));
        clear_error(&error);
        CHECK(!apple_modern_disp_trace_plan_build(root, dram, dram_size, NULL, 0,
                                                  &plan, &error));
        clear_error(&error);
    }
    /* An empty or wrapping exclusion is refused, not ignored. */
    exclusions[0] = (AppleModernAddressRange){ARMIO_PARENT, 0};
    CHECK(!apple_modern_disp_trace_plan_build(served, dram, dram_size,
                                              exclusions, 1, &plan, &error));
    clear_error(&error);
    exclusions[0] = (AppleModernAddressRange){UINT64_MAX - 1, 4};
    CHECK(!apple_modern_disp_trace_plan_build(served, dram, dram_size,
                                              exclusions, 1, &plan, &error));
    clear_error(&error);
    /* NO-DEVICE ORACLE: an exclusion covering the whole /arm-io parent window
     * leaves nothing to observe, and the build is refused rather than mapping
     * a window on top of another device. */
    exclusions[0] = (AppleModernAddressRange){ARMIO_PARENT, UINT64_C(0x2f0000000)};
    CHECK(!apple_modern_disp_trace_plan_build(served, dram, dram_size,
                                              exclusions, 1, &plan, &error));
    clear_error(&error);
    /* One exclusion over disp0 reg[0] only: that window is skipped as another
     * device's, and every other window still maps. */
    exclusions[0] = (AppleModernAddressRange){UINT64_C(0x410000000), 0x1000};
    CHECK(apple_modern_disp_trace_plan_build(served, dram, dram_size,
                                             exclusions, 1, &plan, &error));
    CHECK(error == NULL);
    CHECK(plan.count == expected && plan.mapped == 24);
    CHECK(plan.windows[0].status == APPLE_MODERN_DISP_TRACE_SKIP_DEVICE);
    /* DRAM placed over /arm-io skips every window, so the build is refused. */
    CHECK(!apple_modern_disp_trace_plan_build(served, ARMIO_PARENT,
              UINT64_C(0x2f0000000), NULL, 0, &plan, &error));
    clear_error(&error);
    /* Output that aliases the tree is refused without writing anything. */
    {
        AppleModernBlob alias = {(const uint8_t *)&plan, sizeof(plan)};
        CHECK(!apple_modern_disp_trace_plan_build(alias, dram, dram_size, NULL, 0,
                                                  &plan, &error));
        clear_error(&error);
    }
}

/* ---- the aperture core -------------------------------------------------- */

static void check_core(void)
{
    AppleModernDispTraceCore core;
    uint64_t value = 0xdeadbeef;

    apple_modern_disp_trace_core_reset(&core);
    CHECK(!core.reads && !core.writes && !core.dropped);
    CHECK(!core.record_count && !core.first_window);
    apple_modern_disp_trace_core_reset(NULL); /* must not crash */

    /* A read always answers zero and is always accepted. */
    apple_modern_disp_trace_core_read(&core, 3, 0x40, 4, &value);
    CHECK(value == 0);
    CHECK(core.reads == 1 && core.writes == 0);
    CHECK(core.window_reads[3] == 1 && core.first_window == 4);
    CHECK(core.record_count == 1);
    CHECK(apple_modern_disp_trace_core_recorded(&core, 3, 0x40, false));
    CHECK(!apple_modern_disp_trace_core_recorded(&core, 3, 0x40, true));
    CHECK(!apple_modern_disp_trace_core_recorded(&core, 2, 0x40, false));
    CHECK(!apple_modern_disp_trace_core_recorded(NULL, 3, 0x40, false));
    /* The same (window, offset, direction) is counted but recorded once. */
    for (unsigned i = 0; i < 10; i++) {
        apple_modern_disp_trace_core_read(&core, 3, 0x40, 4, &value);
    }
    CHECK(core.reads == 11 && core.record_count == 1 && !core.dropped);
    /* A write at the same offset is a distinct record. */
    apple_modern_disp_trace_core_write(&core, 3, 0x40, 4);
    CHECK(core.writes == 1 && core.record_count == 2);
    CHECK(core.window_writes[3] == 1);
    CHECK(apple_modern_disp_trace_core_recorded(&core, 3, 0x40, true));
    /* first_window never moves once set. */
    apple_modern_disp_trace_core_read(&core, 0, 0, 1, &value);
    CHECK(core.first_window == 4 && core.window_reads[0] == 1);
    /* Every width 1..8 and every alignment is accepted. */
    for (unsigned size = 1; size <= 8; size++) {
        value = 0x1111;
        apple_modern_disp_trace_core_read(&core, 1, 0x1000 + size, size, &value);
        CHECK(value == 0);
        apple_modern_disp_trace_core_write(&core, 1, 0x2000 + size, size);
    }
    CHECK(core.window_reads[1] == 8 && core.window_writes[1] == 8);
    /* Out-of-range window, zero and oversized widths are ignored entirely. */
    {
        AppleModernDispTraceCore before;
        /* A read with no destination pointer is still a recorded access. */
        apple_modern_disp_trace_core_read(&core, 2, 0, 4, NULL);
        CHECK(core.window_reads[2] == 1);
        before = core;
        apple_modern_disp_trace_core_read(&core, MAXW, 0, 4, &value);
        CHECK(value == 0);
        apple_modern_disp_trace_core_write(&core, MAXW, 0, 4);
        apple_modern_disp_trace_core_read(&core, 2, 0x10, 0, &value);
        apple_modern_disp_trace_core_write(&core, 2, 0x10, 9);
        apple_modern_disp_trace_core_read(NULL, 2, 0x10, 4, &value);
        CHECK(value == 0);
        apple_modern_disp_trace_core_write(NULL, 2, 0x10, 4);
        CHECK(!memcmp(&core, &before, sizeof(core)));
    }
    /* The record list is bounded; everything past the cap is only counted. */
    apple_modern_disp_trace_core_reset(&core);
    for (unsigned i = 0; i < RECS + 50; i++) {
        apple_modern_disp_trace_core_read(&core, 0, i * 4, 4, &value);
    }
    CHECK(core.record_count == RECS);
    CHECK(core.reads == RECS + 50 && core.dropped == 50);
    CHECK(apple_modern_disp_trace_core_recorded(&core, 0, 0, false));
    CHECK(!apple_modern_disp_trace_core_recorded(&core, 0, RECS * 4, false));
    /* Counters saturate instead of wrapping. */
    core.reads = UINT64_MAX;
    core.window_reads[0] = UINT64_MAX;
    core.dropped = UINT64_MAX;
    apple_modern_disp_trace_core_read(&core, 0, 0x7fffffff, 4, &value);
    CHECK(core.reads == UINT64_MAX && core.window_reads[0] == UINT64_MAX &&
          core.dropped == UINT64_MAX);
    /* Reset clears every lane. */
    apple_modern_disp_trace_core_reset(&core);
    for (unsigned w = 0; w < MAXW; w++) {
        CHECK(!core.window_reads[w] && !core.window_writes[w]);
    }
    CHECK(!core.reads && !core.writes && !core.dropped && !core.record_count &&
          !core.first_window);
}

int main(int argc, char **argv)
{
    size_t served_size = 0, stock_size = 0;
    uint8_t *served_data, *stock_data;
    AppleModernBlob served, stock;

    if (argc != 3) {
        fprintf(stderr, "usage: %s SERVED-DTREE STOCK-DTREE\n", argv[0]);
        return 2;
    }
    served_data = slurp(argv[1], &served_size);
    stock_data = slurp(argv[2], &stock_size);
    served = (AppleModernBlob){served_data, served_size};
    stock = (AppleModernBlob){stock_data, stock_size};

    check_profiles(served, stock);
    check_plan(served, stock);
    check_core();

    printf("{\"passed\": true, \"checks\": %u, \"firmware_executed\": false,"
           " \"guest_executed\": false, \"windows\": 29, \"mapped\": 25,"
           " \"compat_overrides_anchored_to_stock\": 21,"
           " \"declared_properties_absent_from_stock\": 5}\n", checks);
    free(served_data);
    free(stock_data);
    return 0;
}
