/* PMP PTD message board and CPU DVFM window gates against the real stock tree.
 * No guest code runs.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-pmp-ptd.h"
#include "hw/arm/apple-silicon/modern-cpu-dvfm.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #x); exit(1); } } while (0)

static void clear_error(Error **error)
{
    CHECK(*error != NULL);
    error_free(*error);
    *error = NULL;
}

static AppleModernBlob load(const char *path)
{
    FILE *f = fopen(path, "rb");
    long size;
    uint8_t *data;
    CHECK(f && !fseek(f, 0, SEEK_END));
    size = ftell(f);
    CHECK(size > 0 && size < (1 << 24) && !fseek(f, 0, SEEK_SET));
    data = malloc(size);
    CHECK(data && fread(data, 1, size, f) == (size_t)size);
    fclose(f);
    return (AppleModernBlob){data, (size_t)size};
}

static uint8_t *property(AppleModernBlob tree, const char *path, const char *name,
                         size_t *size)
{
    AppleModernBlob v;
    Error *error = NULL;
    CHECK(apple_modern_adt_property(tree, path, name, &v, &error));
    if (size) {
        *size = v.size;
    }
    return (uint8_t *)v.data;
}

#define DRAM UINT64_C(0x10000000000)
#define DRAM_SIZE (UINT64_C(8) << 30)

static void ptd_plan(AppleModernBlob tree)
{
    AppleModernPTDPlan plan, junk;
    Error *error = NULL;
    const uint64_t want[2] = {UINT64_C(0x3003c0000), UINT64_C(0x3003d0000)};
    CHECK(apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &plan, &error));
    for (unsigned v = 0; v < 2; v++) {
        AppleModernAddressRange hit[4] = {
            {want[v], 1}, {want[v] + APPLE_MODERN_PTD_SPAN - 1, 1},
            {want[v] - 4, 8}, {want[v] - 1, APPLE_MODERN_PTD_SPAN + 2}};
        AppleModernAddressRange near[2] = {{want[v] - 8, 8}, {want[v] + APPLE_MODERN_PTD_SPAN, 8}};
        CHECK(plan.addresses[v] == want[v]);
        for (unsigned i = 0; i < 4; i++) {
            junk = plan;
            CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, &hit[i], 1, &junk, &error));
            clear_error(&error);
            CHECK(!junk.addresses[0] && !junk.addresses[1]);
        }
        CHECK(apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, near, 2, &junk, &error));
        CHECK(!apple_modern_pmp_ptd_plan_build(tree, want[v], APPLE_MODERN_PTD_SPAN, NULL, 0, &junk, &error));
        clear_error(&error);
        CHECK(!apple_modern_pmp_ptd_plan_build(tree, want[v] + APPLE_MODERN_PTD_SPAN - 1, 2, NULL, 0, &junk, &error));
        clear_error(&error);
    }
    /* Budget, wrap, empty and alias handling. */
    AppleModernAddressRange many[APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1];
    for (unsigned i = 0; i < APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1; i++) {
        many[i] = (AppleModernAddressRange){UINT64_C(0x1000) + i * 8, 8};
    }
    CHECK(apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, many, APPLE_MODERN_MAX_BOARD_EXCLUSIONS, &junk, &error));
    CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, many, APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1, &junk, &error));
    clear_error(&error);
    AppleModernAddressRange wrap = {UINT64_MAX, 8}, empty = {0, 0};
    CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, &wrap, 1, &junk, &error)); clear_error(&error);
    CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, &empty, 1, &junk, &error)); clear_error(&error);
    CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, NULL, 1, &junk, &error)); clear_error(&error);
    CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, 0, NULL, 0, &junk, &error)); clear_error(&error);
    CHECK(!apple_modern_pmp_ptd_plan_build(tree, UINT64_MAX, 2, NULL, 0, &junk, &error)); clear_error(&error);
    CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, NULL, &error)); clear_error(&error);
    CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0,
          (AppleModernPTDPlan *)(void *)tree.data, &error)); clear_error(&error);
    /* ADT mutations (each restored): schema, indices, geometry, translation. */
    struct { const char *path, *name; size_t byte; } flips[] = {
        {"/arm-io/mcc", "compatible", 0}, {"/arm-io/mcc", "pmp_ptd_db_reg_idx", 0},
        {"/arm-io/mcc", "pmp_ptd_update_reg_idx", 0}, {"/arm-io/mcc", "reg", 6 * 16},
        {"/arm-io/mcc", "reg", 6 * 16 + 8 + 1}, {"/arm-io/mcc", "reg", 7 * 16 + 2},
        {"/arm-io/mcc", "reg", 7 * 16 + 8 + 1}, {"/arm-io", "ranges", 8 + 1},
    };
    for (unsigned i = 0; i < sizeof(flips) / sizeof(flips[0]); i++) {
        uint8_t *byte = property(tree, flips[i].path, flips[i].name, NULL) + flips[i].byte;
        *byte ^= 1;
        CHECK(!apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
        clear_error(&error);
        *byte ^= 1;
    }
    CHECK(apple_modern_pmp_ptd_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
}

static void ptd_core(void)
{
    static AppleModernPTDCore core, before;
    uint64_t v = 0x1122334455667788ULL;
    apple_modern_pmp_ptd_core_reset(&core);
    CHECK(!core.reads && !core.writes);
    /* The command words the driver writes, in its order: index 433 then 432. */
    CHECK(apple_modern_pmp_ptd_core_write(&core, 1, 433 * 8, 8, 0));
    CHECK(apple_modern_pmp_ptd_core_write(&core, 1, 432 * 8, 8, 0x1002));
    CHECK(core.writes == 2 && 433 * 8 == 0xd88);
    CHECK(apple_modern_pmp_ptd_core_read(&core, 0, 432 * 16, 8, &v) && v == 0x1002);
    CHECK(apple_modern_pmp_ptd_core_read(&core, 0, 432 * 16 + 8, 8, &v) && v == 0);
    CHECK(apple_modern_pmp_ptd_core_read(&core, 0, 433 * 16, 8, &v) && v == 0);
    /* Quota-request read-modify-write sees the previous lane. */
    CHECK(apple_modern_pmp_ptd_core_write(&core, 1, 424 * 8, 8, 0xaaaabbbbccccddddULL));
    CHECK(apple_modern_pmp_ptd_core_read(&core, 0, 424 * 16, 8, &v) && v == 0xaaaabbbbccccddddULL);
    /* Slots past the Dashboard are stored but not visible anywhere. */
    CHECK(apple_modern_pmp_ptd_core_write(&core, 1, 1024 * 8, 8, 0xdeadbeef));
    CHECK(apple_modern_pmp_ptd_core_write(&core, 1, 2047 * 8, 8, 0xfeedface));
    for (unsigned i = 0; i < APPLE_MODERN_PTD_ENTRIES; i++) {
        CHECK(core.msg[i] == (i == 432 ? 0x1002 : i == 424 ? 0xaaaabbbbccccddddULL : 0));
        CHECK(!core.meta[i]);
    }
    CHECK(core.hidden[0] == 0xdeadbeef && core.hidden[1023] == 0xfeedface);
    /* Ack and quota response entries are untouched: there is no responder. */
    for (unsigned i = 440; i <= 448; i++) {
        CHECK(apple_modern_pmp_ptd_core_read(&core, 0, i * 16, 8, &v) && !v);
        CHECK(apple_modern_pmp_ptd_core_read(&core, 0, i * 16 + 8, 8, &v) && !v);
    }
    before = core;
    v = 0x5a5a5a5a5a5a5a5aULL;
    for (unsigned size = 0; size <= 16; size++) {
        if (size == 8) {
            continue;
        }
        CHECK(!apple_modern_pmp_ptd_core_read(&core, 0, 0, size, &v));
        CHECK(!apple_modern_pmp_ptd_core_write(&core, 1, 0, size, 1));
    }
    CHECK(!apple_modern_pmp_ptd_core_read(&core, 1, 0, 8, &v));          /* Update is write-only */
    CHECK(!apple_modern_pmp_ptd_core_write(&core, 0, 0, 8, 1));          /* Dashboard is read-only */
    CHECK(!apple_modern_pmp_ptd_core_read(&core, 0, 4, 8, &v));          /* misaligned */
    CHECK(!apple_modern_pmp_ptd_core_write(&core, 1, 4, 8, 1));
    CHECK(!apple_modern_pmp_ptd_core_read(&core, 0, APPLE_MODERN_PTD_SPAN, 8, &v));
    CHECK(!apple_modern_pmp_ptd_core_write(&core, 1, APPLE_MODERN_PTD_SPAN, 8, 1));
    CHECK(!apple_modern_pmp_ptd_core_read(&core, 0, UINT64_MAX - 7, 8, &v));
    CHECK(!apple_modern_pmp_ptd_core_read(&core, 2, 0, 8, &v) && !apple_modern_pmp_ptd_core_write(&core, 2, 0, 8, 1));
    CHECK(!apple_modern_pmp_ptd_core_read(NULL, 0, 0, 8, &v) && !apple_modern_pmp_ptd_core_read(&core, 0, 0, 8, NULL));
    CHECK(!apple_modern_pmp_ptd_core_write(NULL, 1, 0, 8, 1));
    CHECK(!apple_modern_pmp_ptd_core_read(&core, 0, 0, 8, &core.msg[3]));  /* value aliasing the core */
    CHECK(v == 0x5a5a5a5a5a5a5a5aULL && !memcmp(&core, &before, sizeof(core)));
    core.reads = core.writes = UINT64_MAX;
    CHECK(apple_modern_pmp_ptd_core_read(&core, 0, 0, 8, &v));
    CHECK(apple_modern_pmp_ptd_core_write(&core, 1, 0, 8, 1));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX);
    apple_modern_pmp_ptd_core_reset(&core);
    CHECK(!core.reads && !core.writes && !core.msg[432] && !core.hidden[0] && !core.hidden[1023]);
}

static void dvfm_plan(AppleModernBlob tree)
{
    AppleModernDVFMPlan plan, junk;
    Error *error = NULL;
    const uint64_t want[2] = {UINT64_C(0x210e78000), UINT64_C(0x211e78000)};
    CHECK(apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &plan, &error));
    for (unsigned w = 0; w < 2; w++) {
        AppleModernAddressRange hit[3] = {
            {want[w], 1}, {want[w] + APPLE_MODERN_DVFM_SPAN - 1, 1}, {want[w] - 8, 16}};
        AppleModernAddressRange near[2] = {{want[w] - 8, 8}, {want[w] + APPLE_MODERN_DVFM_SPAN, 8}};
        CHECK(plan.addresses[w] == want[w]);
        for (unsigned i = 0; i < 3; i++) {
            junk = plan;
            CHECK(!apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, &hit[i], 1, &junk, &error));
            clear_error(&error);
            CHECK(!junk.addresses[0] && !junk.addresses[1]);
        }
        CHECK(apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, near, 2, &junk, &error));
        CHECK(!apple_modern_cpu_dvfm_plan_build(tree, want[w], APPLE_MODERN_DVFM_SPAN, NULL, 0, &junk, &error));
        clear_error(&error);
    }
    AppleModernAddressRange wrap = {UINT64_MAX, 8};
    CHECK(!apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, &wrap, 1, &junk, &error)); clear_error(&error);
    CHECK(!apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, NULL, &error)); clear_error(&error);
    CHECK(!apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, NULL, 1, &junk, &error)); clear_error(&error);
    /* The window must stay inside the cluster of its cpu node: move cpu0's anchor. */
    uint8_t *anchor = property(tree, "/cpus/cpu0", "cpu-impl-reg", NULL) + 3;
    *anchor ^= 1;
    CHECK(!apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    *anchor ^= 1;
    uint8_t *ranges = property(tree, "/arm-io", "ranges", NULL);
    ranges[16 + 5] ^= 1; /* shrink the window range below the DVFM page */
    ranges[16 + 4] ^= 0xff;
    bool shrunk = apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error);
    if (!shrunk) {
        clear_error(&error);
    }
    ranges[16 + 4] ^= 0xff;
    ranges[16 + 5] ^= 1;
    CHECK(apple_modern_cpu_dvfm_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
}

static void dvfm_core(void)
{
    static AppleModernDVFMCore core, before;
    uint64_t v = 7;
    apple_modern_cpu_dvfm_core_reset(&core);
    for (unsigned w = 0; w < 2; w++) {
        for (uint64_t off = 0; off < APPLE_MODERN_DVFM_SPAN; off += 8) {
            CHECK(apple_modern_cpu_dvfm_core_read(&core, w, off, 8, &v) && !v);
        }
    }
    /* The driver's accessor: state index * 0x40 + 8, 64 bits. */
    CHECK(apple_modern_cpu_dvfm_core_write(&core, 0, 1 * 0x40 + 8, 8, 0x123456789abcdef0ULL));
    CHECK(apple_modern_cpu_dvfm_core_read(&core, 0, 0x48, 8, &v) && v == 0x123456789abcdef0ULL);
    CHECK(((v >> 38) & 0x1f) == ((0x123456789abcdef0ULL >> 38) & 0x1f));
    CHECK(apple_modern_cpu_dvfm_core_read(&core, 0, 0x48, 4, &v) && v == 0x9abcdef0);
    CHECK(apple_modern_cpu_dvfm_core_read(&core, 0, 0x4c, 4, &v) && v == 0x12345678);
    CHECK(apple_modern_cpu_dvfm_core_write(&core, 0, 0x4c, 4, 0xa5a5a5a5));
    CHECK(apple_modern_cpu_dvfm_core_read(&core, 0, 0x48, 8, &v) && v == 0xa5a5a5a59abcdef0ULL);
    CHECK(apple_modern_cpu_dvfm_core_write(&core, 0, 0x48, 4, 0x0badf00d));
    CHECK(apple_modern_cpu_dvfm_core_read(&core, 0, 0x48, 8, &v) && v == 0xa5a5a5a50badf00dULL);
    /* Windows are independent. */
    CHECK(apple_modern_cpu_dvfm_core_read(&core, 1, 0x48, 8, &v) && !v);
    before = core;
    v = 0x77;
    for (unsigned size = 0; size <= 16; size++) {
        if (size == 4 || size == 8) {
            continue;
        }
        CHECK(!apple_modern_cpu_dvfm_core_read(&core, 0, 0, size, &v));
        CHECK(!apple_modern_cpu_dvfm_core_write(&core, 0, 0, size, 1));
    }
    CHECK(!apple_modern_cpu_dvfm_core_read(&core, 0, 2, 4, &v) && !apple_modern_cpu_dvfm_core_read(&core, 0, 4, 8, &v));
    CHECK(!apple_modern_cpu_dvfm_core_write(&core, 0, 1, 4, 1) && !apple_modern_cpu_dvfm_core_write(&core, 0, 12, 8, 1));
    CHECK(!apple_modern_cpu_dvfm_core_read(&core, 0, APPLE_MODERN_DVFM_SPAN, 8, &v));
    CHECK(!apple_modern_cpu_dvfm_core_write(&core, 1, APPLE_MODERN_DVFM_SPAN - 4, 8, 1));
    CHECK(!apple_modern_cpu_dvfm_core_read(&core, 2, 0, 8, &v) && !apple_modern_cpu_dvfm_core_write(&core, 2, 0, 8, 1));
    CHECK(!apple_modern_cpu_dvfm_core_read(NULL, 0, 0, 8, &v) && !apple_modern_cpu_dvfm_core_read(&core, 0, 0, 8, NULL));
    CHECK(!apple_modern_cpu_dvfm_core_read(&core, 0, 0, 8, &core.words[0][5]));
    CHECK(v == 0x77 && !memcmp(&core, &before, sizeof(core)));
    core.reads = core.writes = UINT64_MAX;
    CHECK(apple_modern_cpu_dvfm_core_read(&core, 0, 0, 8, &v));
    CHECK(apple_modern_cpu_dvfm_core_write(&core, 0, 0, 8, 1));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX);
    apple_modern_cpu_dvfm_core_reset(&core);
    CHECK(!core.reads && !core.writes && !core.words[0][9]);
}

int main(int argc, char **argv)
{
    AppleModernBlob tree;
    CHECK(argc == 2);
    tree = load(argv[1]);
    ptd_plan(tree);
    ptd_core();
    dvfm_plan(tree);
    dvfm_core();
    free((void *)tree.data);
    printf("PASS %u PTD/DVFM checks; no guest writes or execution\n", checks);
    return 0;
}
