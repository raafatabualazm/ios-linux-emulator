/* PMGR perf-counter register storage gates against the real stock tree.
 * No guest code runs.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-pmgr-storage.h"

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

/* ADT-independent expectations (RegMap reg_index 3 = PMGRCLKGEN_AON_TOP at
 * 0x308200000 and reg_index 1 = PMGR_AON at 0x308280000, plus the group bases
 * read from the perf-groups property on 2026-10-09). */
#define G6_BASE UINT64_C(0x30827b800)
#define G7_BASE UINT64_C(0x3082b4000)
#define G6_COUNTERS 6
#define G7_COUNTERS 69
#define G6_END (0x100 + 0x20 * (G6_COUNTERS - 1) + 4)
#define G7_END (0x100 + 0x20 * (G7_COUNTERS - 1) + 4)

static bool expected_valid(unsigned group, uint64_t offset)
{
    unsigned n = group == 6 ? G6_COUNTERS : G7_COUNTERS;
    if (offset == 0) {
        return true;
    }
    return offset >= 0x100 && offset < 0x100 + 0x20 * n && !((offset - 0x100) % 0x20);
}

static bool slot_valid(const AppleModernPMGRStorageWindow *w, uint64_t slot)
{
    return (w->valid[slot / 64] >> (slot % 64)) & 1;
}

static void plan_exact(AppleModernBlob tree)
{
    AppleModernPMGRStoragePlan plan;
    Error *error = NULL;
    unsigned counted = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &plan, &error));
    CHECK(plan.count == 2 && plan.registers == 7 + 70);
    CHECK(plan.windows[0].group == 6 && plan.windows[0].address == G6_BASE &&
          plan.windows[0].size == G6_END);
    CHECK(plan.windows[1].group == 7 && plan.windows[1].address == G7_BASE &&
          plan.windows[1].size == G7_END + 0);
    for (unsigned w = 0; w < 2; w++) {
        const AppleModernPMGRStorageWindow *win = &plan.windows[w];
        CHECK(win->size % 4 == 0 && win->size <= APPLE_MODERN_PMGR_STORAGE_MAX_SPAN);
        for (uint64_t slot = 0; slot < APPLE_MODERN_PMGR_STORAGE_SLOTS; slot++) {
            bool want = slot < win->size / 4 && expected_valid(win->group, slot * 4);
            CHECK(slot_valid(win, slot) == want);
            counted += want;
        }
    }
    CHECK(counted == plan.registers);
    /* The two windows are disjoint and clear of every DRAM byte. */
    CHECK(plan.windows[0].address + plan.windows[0].size <= plan.windows[1].address ||
          plan.windows[1].address + plan.windows[1].size <= plan.windows[0].address);
}

static void plan_exclusions(AppleModernBlob tree)
{
    AppleModernPMGRStoragePlan plan, junk;
    Error *error = NULL;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &plan, &error));
    for (unsigned w = 0; w < plan.count; w++) {
        uint64_t a = plan.windows[w].address, n = plan.windows[w].size;
        AppleModernAddressRange hit[4] = {{a, 1}, {a + n - 1, 1}, {a - 8, 16}, {a - 1, n + 2}};
        AppleModernAddressRange near[2] = {{a - 8, 8}, {a + n, 8}};
        for (unsigned i = 0; i < 4; i++) {
            junk = plan;
            CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, &hit[i], 1, &junk, &error));
            clear_error(&error);
            CHECK(!junk.count && !junk.registers && !junk.windows[0].address);
        }
        CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, near, 2, &junk, &error));
        CHECK(junk.count == plan.count && junk.registers == plan.registers);
        /* DRAM placed on the window rejects it. */
        CHECK(!apple_modern_pmgr_storage_plan_build(tree, a, n, NULL, 0, &junk, &error));
        clear_error(&error);
        CHECK(!apple_modern_pmgr_storage_plan_build(tree, a + n - 1, 2, NULL, 0, &junk, &error));
        clear_error(&error);
    }
    AppleModernAddressRange wrap = {UINT64_MAX, 8}, empty = {0x1000, 0};
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, &wrap, 1, &junk, &error));
    clear_error(&error);
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, &empty, 1, &junk, &error));
    clear_error(&error);
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, NULL, &error));
    clear_error(&error);
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 1, &junk, &error));
    clear_error(&error);
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, &wrap,
          APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1, &junk, &error));
    clear_error(&error);
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, 0, NULL, 0, &junk, &error));
    clear_error(&error);
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, UINT64_MAX, 8, NULL, 0, &junk, &error));
    clear_error(&error);
    /* Output aliasing the tree or the exclusions is refused without writing. */
    AppleModernPMGRStoragePlan *inside = (AppleModernPMGRStoragePlan *)tree.data;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, inside, &error));
    clear_error(&error);
    AppleModernAddressRange ex[sizeof(plan) / sizeof(AppleModernAddressRange) + 1] = {{0}};
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, ex, 1,
          (AppleModernPMGRStoragePlan *)ex, &error));
    clear_error(&error);
}

/* Tamper with the served tree in place; every edit is undone before the next. */
static void plan_tamper(AppleModernBlob tree)
{
    AppleModernPMGRStoragePlan plan, junk;
    Error *error = NULL;
    size_t groups_size, counters_size, ranges_size, reg_size;
    uint8_t *groups = property(tree, "/arm-io/pmgr", "perf-groups", &groups_size);
    uint8_t *counters = property(tree, "/arm-io/pmgr", "perf-counters", &counters_size);
    uint8_t *ranges = property(tree, "/arm-io", "ranges", &ranges_size);
    uint8_t *reg = property(tree, "/arm-io/pmgr", "reg", &reg_size);
    uint8_t *g6 = groups + 36 * 6, *g7 = groups + 36 * 7;
    uint8_t *c49 = counters + 64 * 49, *c406 = counters + 64 * 406;
    uint8_t saved[64], *copy = malloc(ranges_size);
    CHECK(groups_size == 8 * 36 && counters_size == 420 * 64 && copy);
    CHECK(g6[8] == 2 && g7[8] == 2 && c49[0] == 4 && c49[4] == 7 && c406[0] == 1 &&
          c406[1] == 2 && c406[4] == 7 && c406[5] == 7);
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &plan, &error));

    /* Only group 7 programmed: one window, 70 registers. */
    g6[8] = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.count == 1 && junk.registers == 70 && junk.windows[0].group == 7);
    /* Neither programmed: nothing to model. */
    g7[8] = 0;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    g6[8] = 2; g7[8] = 2;
    /* Flag bit 0 alone (as groups 0-5 have) does not select a group. */
    g7[8] = 1;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.count == 1 && junk.windows[0].group == 6);
    g7[8] = 2;

    /* A type 3 counter is skipped: its register disappears. */
    c49[0] = 3;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.registers == plan.registers - 1);
    CHECK(!slot_valid(&junk.windows[1], 0x100 / 4) && slot_valid(&junk.windows[1], 0x120 / 4));
    c49[0] = 4;
    /* A type 1 counter without flag bit 1 loses its second register (+0x840). */
    c406[1] = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.registers == plan.registers - 1 && !slot_valid(&junk.windows[1], 0x840 / 4) &&
          slot_valid(&junk.windows[1], 0x820 / 4));
    c406[1] = 2;
    /* Its second register follows byte 5 (group2) and offset2: move both to group 6. */
    memcpy(saved, c406, 64);
    c406[1] = 2; c406[5] = 6; c406[12] = 0xc0; c406[13] = 0x01; c406[14] = c406[15] = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.registers == plan.registers && !slot_valid(&junk.windows[1], 0x840 / 4) &&
          slot_valid(&junk.windows[0], 0x1c0 / 4) && junk.windows[0].size == 0x1c4);
    memcpy(c406, saved, 64);
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.registers == plan.registers);

    /* Malformed records are refused. */
    memcpy(saved, c49, 64);
    c49[0] = 5;                                  /* the driver panics on type 5 */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(c49, saved, 64);
    c49[4] = 40;                                 /* group out of range */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(c49, saved, 64);
    c49[8] |= 1;                                 /* unaligned offset */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(c49, saved, 64);
    c49[9] = 0x10; c49[8] = 0;                   /* offset 0x1000 is past the span */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(c49, saved, 64);
    c406[5] = 40;                                /* second group out of range */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    c406[5] = 7;
    memcpy(saved, g7, 36);
    g7[0] = 99;                                  /* reg index past the reg table */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(g7, saved, 36);
    g7[7] = 0x10;                                /* base 0x10034000 is outside reg[1] */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(g7, saved, 36);
    /* Two groups on the same registers overlap. */
    memcpy(saved, g6, 36);
    memcpy(g6, g7, 8);                           /* group 6 -> reg 1, base 0x34000 */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(g6, saved, 36);
    /* A bus range that no longer covers the window refuses it. */
    memcpy(copy, ranges, ranges_size);
    memset(ranges, 0, ranges_size);
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(ranges, copy, ranges_size);
    /* A reg window too small for the group refuses it; an unused one does not matter. */
    memcpy(saved, reg, 32);
    memset(reg + 8, 0, 8);                       /* reg[0].size = 0 (no programmed group) */
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    memset(reg + 16 + 8, 0, 8);                  /* reg[1].size = 0: group 7 cannot fit */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg, saved, 32);
    CHECK(reg_size >= 32);
    free(copy);

    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.count == plan.count && junk.registers == plan.registers);
    for (unsigned w = 0; w < plan.count; w++) {
        CHECK(junk.windows[w].address == plan.windows[w].address &&
              junk.windows[w].size == plan.windows[w].size &&
              junk.windows[w].group == plan.windows[w].group &&
              !memcmp(junk.windows[w].valid, plan.windows[w].valid, sizeof(plan.windows[w].valid)));
    }
}

static void core_stock(AppleModernBlob tree)
{
    static AppleModernPMGRStorageCore core, before;
    AppleModernPMGRStoragePlan plan;
    Error *error = NULL;
    uint64_t v = 7;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &plan, &error));
    core.plan = plan;
    apple_modern_pmgr_storage_core_reset(&core);
    for (unsigned w = 0; w < plan.count; w++) {
        for (uint64_t off = 0; off < plan.windows[w].size; off += 4) {
            bool want = expected_valid(plan.windows[w].group, off);
            v = 7;
            CHECK(!apple_modern_pmgr_storage_core_touched(&core, w, off));
            CHECK(apple_modern_pmgr_storage_core_read(&core, w, off, 4, &v) == want);
            CHECK(want ? v == 0 : v == 7);
            CHECK(apple_modern_pmgr_storage_core_touched(&core, w, off) == want);
        }
    }
    apple_modern_pmgr_storage_core_reset(&core);
    /* The read-modify-write the driver does: read, set bit 2 clear bits 1:0, write. */
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 1, 0x100, 4, (v | 4) & ~3u));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 4, &v) && v == 4);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 1, 0x100, 4, 0xdeadbeef));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 4, &v) && v == 0xdeadbeef);
    /* A 4-byte store keeps only 32 bits; neighbours and the other window stay zero. */
    CHECK(apple_modern_pmgr_storage_core_write(&core, 1, 0x120, 4, 0x1ffffffffULL));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0x120, 4, &v) && v == 0xffffffffu);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0x140, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 0, 0x100, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0, 4, &v) && v == 0);
    /* Holes between listed registers, past the end, 8-byte accesses over a hole,
     * unaligned, odd sizes and bad windows are refused. */
    before = core;
    v = 0x77;
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, 0x104, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_write(&core, 1, 0x104, 4, 1));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 8, &v));   /* slot 0x104 is a hole */
    CHECK(!apple_modern_pmgr_storage_core_write(&core, 1, 0x100, 8, 1));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, 0x102, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, 0x101, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, plan.windows[1].size, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, APPLE_MODERN_PMGR_STORAGE_MAX_SPAN, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_write(&core, 0, plan.windows[0].size, 4, 1));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 2, 0, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_write(&core, 2, 0, 4, 1));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS, 0, 4, &v));
    for (unsigned size = 0; size <= 16; size++) {
        if (size == 4 || size == 8) {
            continue;
        }
        CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, 0x100, size, &v));
        CHECK(!apple_modern_pmgr_storage_core_write(&core, 1, 0x100, size, 1));
    }
    CHECK(!apple_modern_pmgr_storage_core_read(NULL, 1, 0x100, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 4, NULL));
    CHECK(!apple_modern_pmgr_storage_core_write(NULL, 1, 0x100, 4, 1));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 4, &core.reads));
    CHECK(v == 0x77 && !memcmp(&core, &before, sizeof(core)));
    CHECK(!apple_modern_pmgr_storage_core_touched(NULL, 1, 0x100) &&
          !apple_modern_pmgr_storage_core_touched(&core, 2, 0x100) &&
          !apple_modern_pmgr_storage_core_touched(&core, 1, 0x104) &&
          !apple_modern_pmgr_storage_core_touched(&core, 1, 1ULL << 40));
    /* Counters saturate and a reset restores everything but the plan. */
    core.reads = core.writes = UINT64_MAX;
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 4, &v));
    CHECK(apple_modern_pmgr_storage_core_write(&core, 1, 0x100, 4, 1));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX);
    apple_modern_pmgr_storage_core_reset(&core);
    CHECK(!core.reads && !core.writes && core.plan.count == plan.count &&
          !apple_modern_pmgr_storage_core_touched(&core, 1, 0x100));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 4, &v) && v == 0);
    CHECK(core.reads == 1 && core.writes == 0);
}

/* 8-byte accesses on a hand-built window with adjacent listed registers. */
static void core_wide(void)
{
    static AppleModernPMGRStorageCore core;
    uint64_t v = 0;
    core.plan.count = 2;
    core.plan.windows[0].size = 24;
    core.plan.windows[0].valid[0] = 0x2f;        /* slots 0..3 and 5 */
    core.plan.windows[1].size = 8;
    core.plan.windows[1].valid[0] = 0x3;
    apple_modern_pmgr_storage_core_reset(&core);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 0, 8, 8, 0x1122334455667788ULL));
    CHECK(core.values[0][2] == 0x55667788 && core.values[0][3] == 0x11223344);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 0, 8, 8, &v) && v == 0x1122334455667788ULL);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 0, 8, 4, &v) && v == 0x55667788);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 0, 12, 4, &v) && v == 0x11223344);
    CHECK(apple_modern_pmgr_storage_core_touched(&core, 0, 8) && apple_modern_pmgr_storage_core_touched(&core, 0, 12));
    CHECK(!apple_modern_pmgr_storage_core_touched(&core, 0, 0));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 0, 16, 8, &v));    /* slot 4 is a hole */
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 0, 4, 8, &v));     /* unaligned */
    CHECK(apple_modern_pmgr_storage_core_read(&core, 0, 20, 4, &v) && v == 0);
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 0, 24, 4, &v));    /* past the end */
    CHECK(apple_modern_pmgr_storage_core_write(&core, 1, 0, 8, ~0ULL));
    CHECK(core.values[1][0] == 0xffffffffu && core.values[1][1] == 0xffffffffu);
    CHECK(core.values[0][2] == 0x55667788);
}

int main(int argc, char **argv)
{
    AppleModernBlob tree;
    CHECK(argc == 2);
    tree = load(argv[1]);
    plan_exact(tree);
    plan_exclusions(tree);
    plan_tamper(tree);
    core_stock(tree);
    core_wide();
    free((void *)tree.data);
    printf("PASS %u PMGR storage checks; no guest writes or execution\n", checks);
    return 0;
}
