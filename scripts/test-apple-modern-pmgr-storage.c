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
/* NUB_FR_GLOBAL_AP_CONTROLS (reg_index 4, 0x308004000) +0x8, eight 32-bit words. */
#define WAKE_BASE UINT64_C(0x308004008)
#define WAKE_SIZE 0x20
#define WAKE_TAG 0x100
/* PMS_PTS_PTD (reg_index 34, 0x3003c0000): interrupt enable-set / enable-clear banks
 * and the vector-config array, windows 3..5 (tags 0x101..0x103). */
#define PTD_BASE UINT64_C(0x3003c0000)
#define FIXED_WINDOWS 29
#define FIXED_REGISTERS (8 + 32 + 32 + 256 + 2 + 2 + 29 + 5 + 1 + 20)
/* PMGR_SOC_CLUSTER_CTL (reg_index 28, 0x300780000) +0x0 and +0x4: window 6, tag 0x104. */
#define CLUSTER_BASE UINT64_C(0x300780000)
#define CLUSTER_TAG 0x104
/* PMGR_SOC_PWRGATE (reg_index 22, 0x300724000) +0x0 and +0x40: windows 7 and 8, tags 0x105 and 0x106. */
#define PWRGATE_BASE UINT64_C(0x300724000)
/* PMGR_SOC_DPE (reg_index 32, 0x300208000): ten channels; windows 9..18, tags 0x107..0x110.
 * Channel n sits at +0x2400 + 0x400 * n with registers +0x0, +0x200, +0x300; channel 7
 * has no +0x0, so its window starts at +0x4200 with registers +0x0 and +0x100. */
#define DPE_BASE UINT64_C(0x300208000)
#define DPE_TAG 0x107
/* PMC registers in reg_index 43 (0x302000000): the four static-voter vote registers
 * +0x8ac000..+0x8ac00c and the dynamic control register +0x8ac024 (window 19, tag 0x111,
 * size 0x28), and the single register +0x860000 (window 20, tag 0x112, size 4). */
#define PMC_BASE UINT64_C(0x3028ac000)
#define PMC_TAG 0x111
#define PMC_WINDOW 19
#define PMC2_BASE UINT64_C(0x302860000)
#define PMC2_WINDOW 20
/* Ten block-local register pairs (block base + 0x104 and + 0x108), windows 21..30, tags 0x113..0x11c,
 * in the order of the AppleT8140PMGR table at 0xfffffff00b9257c0. */
#define ACG_WINDOW 21
#define ACG_TAG 0x113
static const uint64_t ACG_BASE[10] = {
    UINT64_C(0x408000000), UINT64_C(0x413000000), UINT64_C(0x417000000), UINT64_C(0x38b000000),
    UINT64_C(0x380000000), UINT64_C(0x284000000), UINT64_C(0x288000000), UINT64_C(0x481000000),
    UINT64_C(0x28c000000), UINT64_C(0x396000000)};
static uint64_t dpe_start(unsigned n) { return n == 7 ? 0x4200 : 0x2400 + 0x400 * n; }
static uint32_t dpe_size(unsigned n) { return n == 7 ? 0x104 : 0x304; }
static const struct { uint64_t offset; uint32_t size; } PTD[3] = {
    {0x18200, 0x80}, {0x18300, 0x80}, {0x18400, 0x400}};
#define G6_COUNTERS 6
#define G7_COUNTERS 69
#define G6_END (0x100 + 0x20 * (G6_COUNTERS - 1) + 4)
#define G7_END (0x100 + 0x20 * (G7_COUNTERS - 1) + 4)

static bool expected_valid(unsigned group, uint64_t offset)
{
    unsigned n = group == 6 ? G6_COUNTERS : G7_COUNTERS;
    if (group == WAKE_TAG) {
        return offset < WAKE_SIZE;
    }
    if (group == CLUSTER_TAG) {
        return offset < 8;
    }
    if (group == CLUSTER_TAG + 1 || group == CLUSTER_TAG + 2) {
        return offset == 0;
    }
    if (group == PMC_TAG) {
        return offset < 0x10 || offset == 0x24;
    }
    if (group == PMC_TAG + 1) {
        return offset == 0;
    }
    if (group >= ACG_TAG) {
        return group < ACG_TAG + 10 && offset < 8;
    }
    if (group >= DPE_TAG) {
        unsigned n = group - DPE_TAG;
        return n == 7 ? (offset == 0 || offset == 0x100)
                      : (offset == 0 || offset == 0x200 || offset == 0x300);
    }
    if (group > WAKE_TAG) {
        return offset < PTD[group - WAKE_TAG - 1].size;
    }
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
    CHECK(plan.count == 2 + FIXED_WINDOWS && plan.registers == 7 + 70 + FIXED_REGISTERS);
    CHECK(plan.windows[0].group == 6 && plan.windows[0].address == G6_BASE &&
          plan.windows[0].size == G6_END);
    CHECK(plan.windows[1].group == 7 && plan.windows[1].address == G7_BASE &&
          plan.windows[1].size == G7_END + 0);
    CHECK(plan.windows[2].group == WAKE_TAG && plan.windows[2].address == WAKE_BASE &&
          plan.windows[2].size == WAKE_SIZE);
    CHECK(plan.windows[6].group == CLUSTER_TAG && plan.windows[6].address == CLUSTER_BASE &&
          plan.windows[6].size == 8);
    CHECK(plan.windows[7].group == CLUSTER_TAG + 1 && plan.windows[7].address == PWRGATE_BASE &&
          plan.windows[7].size == 4);
    CHECK(plan.windows[8].group == CLUSTER_TAG + 2 && plan.windows[8].address == PWRGATE_BASE + 0x40 &&
          plan.windows[8].size == 4);
    for (unsigned n = 0; n < 10; n++) {
        CHECK(plan.windows[9 + n].group == DPE_TAG + n &&
              plan.windows[9 + n].address == DPE_BASE + dpe_start(n) &&
              plan.windows[9 + n].size == dpe_size(n));
    }
    CHECK(plan.windows[PMC_WINDOW].group == PMC_TAG && plan.windows[PMC_WINDOW].address == PMC_BASE &&
          plan.windows[PMC_WINDOW].size == 0x28);
    CHECK(plan.windows[PMC2_WINDOW].group == PMC_TAG + 1 && plan.windows[PMC2_WINDOW].address == PMC2_BASE &&
          plan.windows[PMC2_WINDOW].size == 4);
    for (unsigned k = 0; k < 10; k++) {
        CHECK(plan.windows[ACG_WINDOW + k].group == ACG_TAG + k &&
              plan.windows[ACG_WINDOW + k].address == ACG_BASE[k] + 0x104 &&
              plan.windows[ACG_WINDOW + k].size == 8);
    }
    CHECK(plan.count == ACG_WINDOW + 10);
    for (unsigned k = 0; k < 3; k++) {
        CHECK(plan.windows[3 + k].group == WAKE_TAG + 1 + k &&
              plan.windows[3 + k].address == PTD_BASE + PTD[k].offset &&
              plan.windows[3 + k].size == PTD[k].size);
    }
    for (unsigned w = 0; w < plan.count; w++) {
        const AppleModernPMGRStorageWindow *win = &plan.windows[w];
        CHECK(win->size % 4 == 0 && win->size <= APPLE_MODERN_PMGR_STORAGE_MAX_SPAN);
        for (uint64_t slot = 0; slot < APPLE_MODERN_PMGR_STORAGE_SLOTS; slot++) {
            bool want = slot < win->size / 4 && expected_valid(win->group, slot * 4);
            CHECK(slot_valid(win, slot) == want);
            counted += want;
        }
    }
    CHECK(counted == plan.registers);
    /* The windows are pairwise disjoint (the planner also checks DRAM and exclusions). */
    for (unsigned a = 0; a < plan.count; a++) {
        for (unsigned b = a + 1; b < plan.count; b++) {
            CHECK(plan.windows[a].address + plan.windows[a].size <= plan.windows[b].address ||
                  plan.windows[b].address + plan.windows[b].size <= plan.windows[a].address);
        }
    }
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
    CHECK(junk.count == 1 + FIXED_WINDOWS && junk.registers == 70 + FIXED_REGISTERS &&
          junk.windows[0].group == 7 && junk.windows[1].group == WAKE_TAG);
    /* Neither programmed: only the fixed wake-mask window remains. */
    g7[8] = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.count == FIXED_WINDOWS && junk.registers == FIXED_REGISTERS &&
          junk.windows[0].group == WAKE_TAG);
    g6[8] = 2; g7[8] = 2;
    /* Flag bit 0 alone (as groups 0-5 have) does not select a group. */
    g7[8] = 1;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.count == 1 + FIXED_WINDOWS && junk.windows[0].group == 6 &&
          junk.windows[1].group == WAKE_TAG);
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
    CHECK(reg_size >= 5 * 16);
    /* The wake-mask window needs +0x8..+0x28 inside reg[4]. */
    memcpy(saved, reg + 4 * 16, 16);
    reg[4 * 16 + 8] = 0x28; reg[4 * 16 + 9] = 0;      /* size 0x28 just fits */
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[4 * 16 + 8] = 0x27;                             /* one byte short */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 4 * 16, saved, 16);
    /* The PTD windows need +0x18200..+0x18800 inside reg[34]. */
    CHECK(reg_size >= 35 * 16);
    memcpy(saved, reg + 34 * 16, 16);
    reg[34 * 16 + 8] = 0x00; reg[34 * 16 + 9] = 0x88; reg[34 * 16 + 10] = 0x01;   /* 0x18800 */
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[34 * 16 + 9] = 0x87; reg[34 * 16 + 8] = 0xff;                              /* 0x187ff */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 34 * 16, saved, 16);
    /* The cluster-control registers need reg[28] to hold at least 8 bytes. */
    CHECK(reg_size >= 29 * 16);
    memcpy(saved, reg + 28 * 16, 16);
    memset(reg + 28 * 16 + 8, 0, 8);
    reg[28 * 16 + 8] = 8;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[28 * 16 + 8] = 7;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 28 * 16, saved, 16);
    /* PwrGate +0x40 needs reg[22] to hold at least 0x44 bytes. */
    CHECK(reg_size >= 23 * 16);
    memcpy(saved, reg + 22 * 16, 16);
    memset(reg + 22 * 16 + 8, 0, 8);
    reg[22 * 16 + 8] = 0x44;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[22 * 16 + 8] = 0x43;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 22 * 16, saved, 16);
    /* The last DPE register (+0x4b00) needs reg[32] to hold 0x4b04 bytes. */
    CHECK(reg_size >= 33 * 16);
    memcpy(saved, reg + 32 * 16, 16);
    memset(reg + 32 * 16 + 8, 0, 8);
    reg[32 * 16 + 8] = 0x04; reg[32 * 16 + 9] = 0x4b;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[32 * 16 + 8] = 0x03;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 32 * 16, saved, 16);
    /* The PMC window needs reg[43] to hold 0x8ac028 bytes (the +0x24 register ends there). */
    CHECK(reg_size >= 44 * 16);
    memcpy(saved, reg + 43 * 16, 16);
    memset(reg + 43 * 16 + 8, 0, 8);
    reg[43 * 16 + 8] = 0x28; reg[43 * 16 + 9] = 0xc0; reg[43 * 16 + 10] = 0x8a;      /* 0x8ac028 */
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[43 * 16 + 8] = 0x27;                                                           /* one byte short */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    reg[43 * 16 + 8] = 0x00; reg[43 * 16 + 9] = 0xc0; reg[43 * 16 + 10] = 0x86;       /* 0x86c000 */
    reg[43 * 16 + 11] = 0;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 43 * 16, saved, 16);
    /* The block-local register pairs must lie inside the /arm-io bus ranges: the first range
     * (child 0 -> 0x210000000, 0x2f0000000 bytes) covers all but one of them; cutting it
     * to 0x1f0000000 bytes (end 0x400000000) leaves 0x413000104 uncovered, and no other
     * range reaches it. Cutting it to the exact end of the last pair is not tested here:
     * pairs above 0x413000104 fail first. */
    {
        uint64_t original = 0, cut = UINT64_C(0x1f0000000);
        for (unsigned i = 0; i < 8; i++) {
            original |= (uint64_t)ranges[16 + i] << (8 * i);
        }
        CHECK(original == UINT64_C(0x2f0000000));
        for (unsigned i = 0; i < 8; i++) {
            ranges[16 + i] = (uint8_t)(cut >> (8 * i));
        }
        CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
        clear_error(&error);
        for (unsigned i = 0; i < 8; i++) {
            ranges[16 + i] = (uint8_t)(original >> (8 * i));
        }
        CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    }
    /* The window lists rails 0..3; an ADT whose voter-rail-data disagrees is refused. */
    {
        size_t rails_size;
        uint8_t *rails = property(tree, "/arm-io/pmgr", "voter-rail-data", &rails_size);
        CHECK(rails_size == 4 * 24 && rails[0] == 0 && rails[24] == 1 && rails[48] == 2 &&
              rails[72] == 3 && !rails[1] && !rails[25] && !rails[49] && !rails[73]);
        for (unsigned i = 0; i < 4; i++) {
            rails[24 * i] ^= 4;                                  /* wrong low byte of the rail index */
            CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
            clear_error(&error);
            rails[24 * i] ^= 4;
            rails[24 * i + 1] = 1;                                /* rail index above 255 */
            CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
            clear_error(&error);
            rails[24 * i + 1] = 0;
        }
        CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    }
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
    /* The wake-source mask: eight adjacent words, so 4- and 8-byte accesses both work. */
    for (unsigned word = 0; word < 8; word++) {
        CHECK(apple_modern_pmgr_storage_core_write(&core, 2, 4 * word, 4, 0x11111111u * (word + 1)));
    }
    for (unsigned word = 0; word < 8; word++) {
        CHECK(apple_modern_pmgr_storage_core_read(&core, 2, 4 * word, 4, &v) &&
              v == 0x11111111u * (word + 1));
    }
    CHECK(apple_modern_pmgr_storage_core_read(&core, 2, 8, 8, &v) && v == 0x4444444433333333ULL);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 2, 0x18, 8, 0xa5a5a5a55a5a5a5aULL));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 2, 0x1c, 4, &v) && v == 0xa5a5a5a5u);
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 2, WAKE_SIZE, 4, &v));   /* the status words */
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 2, 0x1c, 8, &v));        /* straddles the end */
    CHECK(apple_modern_pmgr_storage_core_read(&core, 1, 0x100, 4, &v) && v == 0xdeadbeef);
    /* The PTD interrupt block, as ApplePMGR's opcode 3 drives it for entry e = 5 with
     * ptd-driver-version 1: read-modify-write of the 5-bit vector field of lane 1 of
     * the word at 0x18400 + (e / 8) * 4 + ((e / 4) & 1) * 0x200, then write
     * 1 << (e % 32) to the enable-set bank word e / 32. */
    {
        unsigned e = 5, lane = e % 4;
        uint64_t config = (e / 8) * 4 + ((e / 4) & 1) * 0x200, bank = (e / 32) * 4;
        CHECK(config == 0x200 && bank == 0);
        CHECK(apple_modern_pmgr_storage_core_read(&core, 5, config, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_write(&core, 5, config, 4,
              (v & ~(0x1fULL << (8 * lane))) | (0x13ULL << (8 * lane))));
        CHECK(apple_modern_pmgr_storage_core_read(&core, 5, config, 4, &v) && v == 0x1300);
        CHECK(apple_modern_pmgr_storage_core_write(&core, 3, bank, 4, 1u << (e % 32)));
        CHECK(apple_modern_pmgr_storage_core_read(&core, 3, bank, 4, &v) && v == 0x20);
        CHECK(apple_modern_pmgr_storage_core_write(&core, 4, bank, 4, 1u << (e % 32)));
        CHECK(apple_modern_pmgr_storage_core_read(&core, 4, bank, 4, &v) && v == 0x20);
        /* Entry 1023 is the last bit of the last word of each bank. */
        CHECK(apple_modern_pmgr_storage_core_write(&core, 3, 0x7c, 4, 0x80000000u));
        CHECK(apple_modern_pmgr_storage_core_read(&core, 3, 0x7c, 4, &v) && v == 0x80000000u);
        CHECK(!apple_modern_pmgr_storage_core_read(&core, 3, 0x80, 4, &v));   /* the enable-clear bank starts elsewhere */
        CHECK(apple_modern_pmgr_storage_core_write(&core, 5, 0x3fc, 4, 0xffffffffu));
        CHECK(!apple_modern_pmgr_storage_core_write(&core, 5, 0x400, 4, 1));
        /* The windows are separate storage. */
        CHECK(apple_modern_pmgr_storage_core_read(&core, 3, 0, 4, &v) && v == 0x20);
        CHECK(apple_modern_pmgr_storage_core_read(&core, 4, 4, 4, &v) && v == 0);
    }
    /* PMGR_SOC_CLUSTER_CTL +0, as the cluster power routine drives it: read, write
     * ((v & ~0xf) | 0xf), then the wait polls (v & 0x10) == 0. */
    CHECK(apple_modern_pmgr_storage_core_read(&core, 6, 0, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 6, 0, 4, (v & ~0xfULL) | 0xf));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 6, 0, 4, &v) && v == 0xf && !(v & 0x10));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 6, 4, 4, &v) && v == 0);  /* the index-1 register */
    CHECK(apple_modern_pmgr_storage_core_write(&core, 6, 4, 4, 0xf));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 6, 0, 8, &v) && v == 0xf0000000fULL);
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 6, 8, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 6, 8, 8, &v));
    /* PMGR_SOC_PWRGATE +0x0 and +0x40, as the wrapper drives them: read, then write
     * with bit 31 set; the registers in between are not listed. */
    CHECK(apple_modern_pmgr_storage_core_read(&core, 7, 0, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 7, 0, 4, v | 0x80000000u));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 7, 0, 4, &v) && v == 0x80000000u);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 8, 0, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 8, 0, 4, v | 0x80000000u));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 8, 0, 4, &v) && v == 0x80000000u);
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 7, 4, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 8, 4, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, plan.count, 0, 4, &v));
    /* PMGR_SOC_DPE: per channel read-modify-write setting bit 0 at +0x200, +0x0 and
     * +0x300 (channel 7: +0x200 and +0x300 of its 0x4000 base only). */
    CHECK(apple_modern_pmgr_storage_core_read(&core, 9, 0x200, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 9, 0x200, 4, v | 1));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 9, 0x200, 4, &v) && v == 1);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 9, 0, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 9, 0x300, 4, &v) && v == 0);
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 9, 0x100, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 9, 0x204, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 9, 0x304, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 9, 0x200, 8, &v));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 16, 0, 4, &v) && apple_modern_pmgr_storage_core_read(&core, 16, 0x100, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 16, 0x200, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 16, 4, 4, &v));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 18, 0x300, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 18, 0x304, 4, &v));
    /* PMC static-voter vote registers: ApplePMC::_enableStaticVoterInterface, for each
     * of the agents PMP (bit 0), CLPC (bit 1) and AP (bit 3) and each rail 0..3 of the
     * agent's mask, reads the rail's register, sets the agent's bit and writes it back
     * (12 read-modify-writes on 4 registers); each register ends at 0xb. */
    {
        static const unsigned bits[3] = {0, 1, 3}, previous[3] = {0, 1, 3};
        for (unsigned a = 0; a < 3; a++) {
            for (unsigned rail = 0; rail < 4; rail++) {
                CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 4 * rail, 4, &v));
                CHECK(v == previous[a]);
                CHECK(apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 4 * rail, 4,
                      v | (1u << bits[a])));
            }
        }
        for (unsigned rail = 0; rail < 4; rail++) {
            CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 4 * rail, 4, &v) && v == 0xb);
        }
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 8, 8, &v) && v == 0x0000000b0000000bULL);
        /* The dynamic voter interface (ApplePMC flag bit 4): read-modify-write of +0x24 to
         * (v & ~3) | enable << 1 | flag with enable = 1 and flag = 1 on this device, then a
         * write of 0xffffffff to PMC +0x60000 (reg[43] +0x860000). */
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x24, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x24, 4, (v & ~3ULL) | 2 | 1));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x24, 4, &v) && v == 3);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x24, 4, 0xfffffffdu));
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC2_WINDOW, 0, 4, 0xffffffffu));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC2_WINDOW, 0, 4, &v) && v == 0xffffffffu);
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x24, 4, &v) && v == 0xfffffffdu);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x24, 4, 3));
        /* Nothing else exists: the gap after the vote registers, the kind 1 and kind 3
         * registers (+0x20, +0x28), 8-byte accesses over a hole, and the end of both windows. */
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x10, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x10, 4, 1));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0xc, 8, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x1c, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x20, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x20, 8, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x28, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x24, 8, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC2_WINDOW, 4, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC2_WINDOW, 0, 8, &v));
        /* A neighbouring window is separate storage. */
        CHECK(apple_modern_pmgr_storage_core_read(&core, 18, 0x300, 4, &v));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0, 4, &v) && v == 0xb);
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x24, 4, &v) && v == 3);
    }
    /* The T8140 PS-write hook, entry 1 (PMGR_SOC +0x280, block 0x413000000): power-up sets
     * bit 0 of both registers by read-modify-write, power-down clears it; no poll. */
    {
        unsigned w = ACG_WINDOW + 1;
        CHECK(plan.windows[w].address == UINT64_C(0x413000104));
        for (unsigned r = 0; r < 2; r++) {
            CHECK(apple_modern_pmgr_storage_core_read(&core, w, 4 * r, 4, &v) && v == 0);
            CHECK(apple_modern_pmgr_storage_core_write(&core, w, 4 * r, 4, v | 1));
            CHECK(apple_modern_pmgr_storage_core_read(&core, w, 4 * r, 4, &v) && v == 1);
        }
        CHECK(apple_modern_pmgr_storage_core_read(&core, w, 0, 8, &v) && v == 0x100000001ULL);
        CHECK(apple_modern_pmgr_storage_core_read(&core, w, 4, 4, &v));
        CHECK(apple_modern_pmgr_storage_core_write(&core, w, 4, 4, v & ~1u));
        CHECK(apple_modern_pmgr_storage_core_read(&core, w, 0, 8, &v) && v == 1);
        /* The ten pairs are separate storage; each lists exactly its two registers. */
        for (unsigned k = 0; k < 10; k++) {
            CHECK(apple_modern_pmgr_storage_core_write(&core, ACG_WINDOW + k, 0, 8,
                  0x5500000000ULL + k));
        }
        for (unsigned k = 0; k < 10; k++) {
            CHECK(apple_modern_pmgr_storage_core_read(&core, ACG_WINDOW + k, 0, 8, &v) &&
                  v == 0x5500000000ULL + k);
            CHECK(!apple_modern_pmgr_storage_core_read(&core, ACG_WINDOW + k, 8, 4, &v));
            CHECK(!apple_modern_pmgr_storage_core_write(&core, ACG_WINDOW + k, 8, 4, 1));
            CHECK(!apple_modern_pmgr_storage_core_read(&core, ACG_WINDOW + k, 4, 8, &v));
            CHECK(!apple_modern_pmgr_storage_core_read(&core, ACG_WINDOW + k, 2, 4, &v));
        }
        CHECK(!apple_modern_pmgr_storage_core_read(&core, plan.count, 0, 4, &v));
    }
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
    CHECK(!apple_modern_pmgr_storage_core_read(&core, plan.count, 0, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_write(&core, plan.count, 0, 4, 1));
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
          !apple_modern_pmgr_storage_core_touched(&core, plan.count, 0x100) &&
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
