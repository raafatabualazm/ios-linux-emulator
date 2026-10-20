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
/*
 * fixed_windows[] in modern-pmgr-storage.c, in table order: MISC +0x8 (8 regs),
 * the three PTD interrupt banks (32 + 32 + 256), CLUSTER_CTL (5), nine DPE
 * channels of 6 registers plus the ch7 window of 5, the PMC vote/DVFM/DVMR
 * windows (7 + 1 + 2 + 1), and the full PWRGATE and TVM banks (4096 each).
 */
#define FIXED_WINDOWS 21
#define FIXED_REGISTERS (8 + 32 + 32 + 256 + 5 + 9 * 6 + 5 + 7 + 1 + 2 + 1 + 4096 + 4096)
/*
 * Served alongside on every tree: the ten AXI2AF block pairs (+0x104/+0x108),
 * the two full ACC CPM_PWRCTL banks (reg[5]/reg[14], 0x2000 each) and the six
 * 0x10-byte per-core / P-cluster CPM counter windows (+0x9000 / +0x8000).
 */
#define EXTRA_WINDOWS (10 + 2 + 6)
#define EXTRA_REGISTERS (10 * 2 + 2 * (0x2000 / 4) + 6 * 4)
/* Five ADT cluster-control registers (reg_index 28): window 6, tag 0x104. */
#define CLUSTER_BASE UINT64_C(0x300780000)
#define CLUSTER_TAG 0x104
/* PMGR_SOC_DPE: ten channels; windows 7..16, tags 0x105..0x10e. */
#define DPE_BASE UINT64_C(0x300208000)
#define DPE_TAG 0x105
/* PMC: windows 17..20, tags 0x10f..0x112. */
#define PMC_BASE UINT64_C(0x3028ac000)
#define PMC_TAG 0x10f
#define PMC_WINDOW 17
#define PMC2_BASE UINT64_C(0x302860000)
#define PMC2_WINDOW 18
#define PMC3_BASE UINT64_C(0x3028a4000)
#define PMC3_WINDOW 19
#define PMC4_BASE UINT64_C(0x3028a9c14)
#define PMC4_WINDOW 20
/* PMGR_SOC_PWRGATE full 0x4000: window 21, tag 0x113. */
#define PWRGATE_BASE UINT64_C(0x300724000)
#define PWRGATE_WINDOW 21
#define PWRGATE_TAG 0x113
/* PMGR_SOC_TVM full 0x4000: window 22, tag 0x114. */
#define TVM_BASE UINT64_C(0x300760000)
#define TVM_WINDOW 22
#define TVM_TAG 0x114
/* ACG pairs: windows 23..32, tags 0x115..0x11e. */
#define ACG_WINDOW 23
#define ACG_TAG 0x115
static const uint64_t ACG_BASE[10] = {
    UINT64_C(0x408000000), UINT64_C(0x413000000), UINT64_C(0x417000000), UINT64_C(0x38b000000),
    UINT64_C(0x380000000), UINT64_C(0x284000000), UINT64_C(0x288000000), UINT64_C(0x481000000),
    UINT64_C(0x28c000000), UINT64_C(0x396000000)};
static uint64_t dpe_start(unsigned n) { return n == 7 ? 0x4200 : 0x2400 + 0x400 * n; }
static uint32_t dpe_size(unsigned n) { return n == 7 ? 0x110 : 0x310; }
static const struct { uint64_t offset; uint32_t size; } PTD[3] = {
    {0x18200, 0x80}, {0x18300, 0x80}, {0x18400, 0x400}};
#define G6_COUNTERS 6
#define G7_COUNTERS 69
#define G6_END 0x1b8
#define G7_END 0x998

#include "test-apple-modern-pmgr-counter-table.inc"
static bool expected_valid(unsigned group, uint64_t offset)
{
    if (group < 8) {
        for (unsigned i = 0; i < counter_expect[group].count; i++) {
            if (counter_expect[group].offsets[i] == offset) {
                return true;
            }
        }
        return false;
    }
    if (group == WAKE_TAG) {
        return offset < WAKE_SIZE;
    }
    if (group == CLUSTER_TAG) {
        return offset < 20;
    }
    if (group == PMC_TAG) {
        return offset < 0x10 || offset == 0x20 || offset == 0x24 || offset == 0x28;
    }
    if (group == PMC_TAG + 1) {
        return offset == 0;
    }
    if (group == PMC_TAG + 2) {
        return offset == 0 || offset == 0x20;
    }
    if (group == PMC_TAG + 3) {
        return offset == 0;
    }
    if (group == PWRGATE_TAG) {
        return offset < 0x4000; /* the whole bank is served (MEASURED +0x60) */
    }
    if (group == TVM_TAG) {
        return offset < 0x4000;
    }
    if (group >= 0x200 && group < 0x208) {
        const unsigned sizes[8] = {
            0x2000, 0x2000, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        };
        return offset < sizes[group - 0x200];
    }
    if (group >= ACG_TAG) {
        return group < ACG_TAG + 10 && offset < 8;
    }
    if (group >= DPE_TAG) {
        unsigned n = group - DPE_TAG;
        return n == 7 ? (offset == 0 || offset == 0x100 || offset == 0x104 ||
                         offset == 0x108 || offset == 0x10c)
                      : (offset == 0 || offset == 0x200 || offset == 0x300 || offset == 0x304 || offset == 0x308 || offset == 0x30c);
    }
    if (group > WAKE_TAG && group <= WAKE_TAG + 3) {
        return offset < PTD[group - WAKE_TAG - 1].size;
    }
    return false;
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
    CHECK(plan.count == 8 + FIXED_WINDOWS + EXTRA_WINDOWS && plan.registers == 1787 + FIXED_REGISTERS + EXTRA_REGISTERS);
    CHECK(plan.windows[0].group == 6 && plan.windows[0].address == G6_BASE &&
          plan.windows[0].size == G6_END);
    CHECK(plan.windows[1].group == 7 && plan.windows[1].address == G7_BASE &&
          plan.windows[1].size == G7_END + 0);
    CHECK(plan.windows[2].group == WAKE_TAG && plan.windows[2].address == WAKE_BASE &&
          plan.windows[2].size == WAKE_SIZE);
    CHECK(plan.windows[6].group == CLUSTER_TAG && plan.windows[6].address == CLUSTER_BASE &&
          plan.windows[6].size == 20);
    for (unsigned n = 0; n < 10; n++) {
        CHECK(plan.windows[7 + n].group == DPE_TAG + n &&
              plan.windows[7 + n].address == DPE_BASE + dpe_start(n) &&
              plan.windows[7 + n].size == dpe_size(n));
    }
    CHECK(plan.windows[PMC_WINDOW].group == PMC_TAG && plan.windows[PMC_WINDOW].address == PMC_BASE &&
          plan.windows[PMC_WINDOW].size == 0x2c);
    CHECK(plan.windows[PMC2_WINDOW].group == PMC_TAG + 1 && plan.windows[PMC2_WINDOW].address == PMC2_BASE &&
          plan.windows[PMC2_WINDOW].size == 4);
    CHECK(plan.windows[PMC3_WINDOW].group == PMC_TAG + 2 && plan.windows[PMC3_WINDOW].address == PMC3_BASE &&
          plan.windows[PMC3_WINDOW].size == 0x24);
    CHECK(plan.windows[PMC4_WINDOW].group == PMC_TAG + 3 && plan.windows[PMC4_WINDOW].address == PMC4_BASE &&
          plan.windows[PMC4_WINDOW].size == 4);
    CHECK(plan.windows[PWRGATE_WINDOW].group == PWRGATE_TAG && plan.windows[PWRGATE_WINDOW].address == PWRGATE_BASE &&
          plan.windows[PWRGATE_WINDOW].size == 0x4000);
    CHECK(plan.windows[TVM_WINDOW].group == TVM_TAG && plan.windows[TVM_WINDOW].address == TVM_BASE &&
          plan.windows[TVM_WINDOW].size == 0x4000);
    for (unsigned k = 0; k < 10; k++) {
        CHECK(plan.windows[ACG_WINDOW + k].group == ACG_TAG + k &&
              plan.windows[ACG_WINDOW + k].address == ACG_BASE[k] + 0x104 &&
              plan.windows[ACG_WINDOW + k].size == 8);
    }
    CHECK(plan.count == ACG_WINDOW + 10 + 6 + 8);
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
            /*
             * An exclusion on a window hands that span to the device that owns
             * it: the window is omitted and counted, every other window stands
             * (0c747cd; before it the whole plan was refused).
             */
            unsigned dropped = 0, dropped_regs = 0;
            for (unsigned k = 0; k < plan.count; k++) {
                const AppleModernPMGRStorageWindow *o = &plan.windows[k];
                if (o->address < hit[i].physical_address + hit[i].size &&
                    hit[i].physical_address < o->address + o->size) {
                    dropped++;
                    for (unsigned m = 0; m < APPLE_MODERN_PMGR_STORAGE_MASKS; m++) {
                        dropped_regs += __builtin_popcountll(o->valid[m]);
                    }
                }
            }
            CHECK(dropped >= 1);
            junk = plan;
            CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, &hit[i], 1, &junk, &error));
            CHECK(junk.omitted == dropped && junk.count == plan.count - dropped &&
                  junk.registers == plan.registers - dropped_regs);
            for (unsigned k = 0; k < junk.count; k++) {
                CHECK(!(junk.windows[k].address < hit[i].physical_address + hit[i].size &&
                        hit[i].physical_address < junk.windows[k].address + junk.windows[k].size));
            }
        }
        CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, near, 2, &junk, &error));
        CHECK(junk.count == plan.count && junk.registers == plan.registers && !junk.omitted);
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

    /* Group flags change placement order, not the later enable-register set. */
    g6[8] = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.count == 8 + FIXED_WINDOWS + EXTRA_WINDOWS && junk.registers == 1787 + FIXED_REGISTERS + EXTRA_REGISTERS &&
          junk.windows[0].group == 7 && junk.windows[1].group == WAKE_TAG);
    /* Neither initially programmed: fixed windows precede all eight groups. */
    g7[8] = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.count == 8 + FIXED_WINDOWS + EXTRA_WINDOWS && junk.registers == 1787 + FIXED_REGISTERS + EXTRA_REGISTERS &&
          junk.windows[0].group == WAKE_TAG);
    g6[8] = 2; g7[8] = 2;
    /* Flag bit 0 alone defers a group to the appended enable groups. */
    g7[8] = 1;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.count == 8 + FIXED_WINDOWS + EXTRA_WINDOWS && junk.windows[0].group == 6 &&
          junk.windows[1].group == WAKE_TAG);
    g7[8] = 2;

    /* A type 3 counter is skipped: its register disappears. */
    c49[0] = 3;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.registers == plan.registers - 3);
    CHECK(!slot_valid(&junk.windows[1], 0x100 / 4) && slot_valid(&junk.windows[1], 0x120 / 4));
    c49[0] = 4;
    /* A type 1 counter without flag bit 1 loses its second register (+0x840). */
    c406[1] = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.registers == plan.registers - 3 && !slot_valid(&junk.windows[1], 0x840 / 4) &&
          slot_valid(&junk.windows[1], 0x820 / 4));
    c406[1] = 2;
    /* Its second register follows byte 5 (group2) and offset2: move both to group 6. */
    memcpy(saved, c406, 64);
    c406[1] = 2; c406[5] = 6; c406[12] = 0xc0; c406[13] = 0x01; c406[14] = c406[15] = 0;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    CHECK(junk.registers == plan.registers && !slot_valid(&junk.windows[1], 0x840 / 4) &&
          slot_valid(&junk.windows[0], 0x1c0 / 4) && junk.windows[0].size == 0x1d8);
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
    c49[9] = 0x40; c49[8] = 0;                   /* offset 0x4000 is past the span */
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
    /* Both initial-programming and later-enable group windows must fit. */
    memcpy(saved, reg, 32);
    memset(reg + 8, 0, 8);                       /* reg[0].size = 0 (groups 1..4) */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg, saved, 32);
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
    /* Five cluster-control registers must fit in reg[28]. */
    CHECK(reg_size >= 29 * 16);
    memcpy(saved, reg + 28 * 16, 16);
    memset(reg + 28 * 16 + 8, 0, 8);
    reg[28 * 16 + 8] = 20;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[28 * 16 + 8] = 19;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 28 * 16, saved, 16);
    /* The whole PWRGATE bank is served: reg[22] must hold 0x4000 bytes (MEASURED +0x60 hang). */
    CHECK(reg_size >= 23 * 16);
    memcpy(saved, reg + 22 * 16, 16);
    memset(reg + 22 * 16 + 8, 0, 8);
    reg[22 * 16 + 8] = 0x00; reg[22 * 16 + 9] = 0x40;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[22 * 16 + 8] = 0xff; reg[22 * 16 + 9] = 0x3f;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 22 * 16, saved, 16);
    /* Complex bring-up dispatches by TVM index across the bank (MEASURED), so reg[25] must span 0x4000 bytes. */
    CHECK(reg_size >= 26 * 16);
    memcpy(saved, reg + 25 * 16, 16);
    memset(reg + 25 * 16 + 8, 0, 8);
    reg[25 * 16 + 8] = 0x00; reg[25 * 16 + 9] = 0x40;  /* 0x4000: the whole TVM bank is served */
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[25 * 16 + 8] = 0xff; reg[25 * 16 + 9] = 0x3f;  /* 0x3fff: one byte short of the bank */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 25 * 16, saved, 16);
    /* Only the AVE soc-clusters record selects a TVM (flags bit 2, index 0xb); any other
     * selection, a different index or a different schema is refused. */
    {
        size_t clusters_size;
        uint8_t *clusters = property(tree, "/arm-io/pmgr", "soc-clusters", &clusters_size);
        CHECK(clusters_size == 5 * 28 && clusters[28 * 2 + 2] == 5 && clusters[28 * 2 + 0xb] == 0xb);
        for (unsigned i = 0; i < 5; i++) {
            clusters[28 * i] ^= 0x80;
            CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
            clear_error(&error);
            clusters[28 * i] ^= 0x80;
            uint8_t flags = clusters[28 * i + 2], index = clusters[28 * i + 0xb];
            if (i != 2) {
                clusters[28 * i + 2] = flags | 4;                  /* a second record selecting a TVM */
                clusters[28 * i + 0xb] = 9;
                CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
                clear_error(&error);
                clusters[28 * i + 0xb] = 5;                        /* index 4 and 5 are skipped by the driver */
                CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
                CHECK(junk.count == plan.count && junk.registers == plan.registers);
                clusters[28 * i + 0xb] = 4;
                CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
            } else {
                clusters[28 * i + 0xb] = 9;                        /* AVE with another index */
                CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
                clear_error(&error);
                clusters[28 * i + 0xb] = 0xb;
                clusters[28 * i + 2] = flags & ~4;                 /* AVE no longer selects one */
                CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
                clear_error(&error);
            }
            clusters[28 * i + 2] = flags;
            clusters[28 * i + 0xb] = index;
        }
        /* Everything is restored: the stock records again. */
        CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
        CHECK(clusters[28 * 2 + 2] == 5 && clusters[28 * 2 + 0xb] == 0xb);
    }
    /* The last DPE register (+0x4b08) needs reg[32] to hold 0x4b10 bytes. */
    CHECK(reg_size >= 33 * 16);
    memcpy(saved, reg + 32 * 16, 16);
    memset(reg + 32 * 16 + 8, 0, 8);
    reg[32 * 16 + 8] = 0x10; reg[32 * 16 + 9] = 0x4b;
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[32 * 16 + 8] = 0x0f;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    memcpy(reg + 32 * 16, saved, 16);
    /* reg[43] must hold the PMC cells and the final group5 data word. */
    CHECK(reg_size >= 44 * 16);
    memcpy(saved, reg + 43 * 16, 16);
    memset(reg + 43 * 16 + 8, 0, 8);
    reg[43 * 16 + 8] = 0xf8; reg[43 * 16 + 9] = 0x01; reg[43 * 16 + 10] = 0x90;      /* 0x9001f8 */
    CHECK(apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    reg[43 * 16 + 8] = 0xf7;                                                           /* one byte short */
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    reg[43 * 16 + 8] = 0x00; reg[43 * 16 + 9] = 0xc0; reg[43 * 16 + 10] = 0x86;       /* 0x86c000 */
    reg[43 * 16 + 11] = 0;
    CHECK(!apple_modern_pmgr_storage_plan_build(tree, DRAM, DRAM_SIZE, NULL, 0, &junk, &error));
    clear_error(&error);
    reg[43 * 16 + 8] = 0x00; reg[43 * 16 + 9] = 0x40; reg[43 * 16 + 10] = 0x8a;       /* 0x8a4000: no DVMR */
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
    for (unsigned i = 2; i < 5; i++) {
        CHECK(apple_modern_pmgr_storage_core_read(&core, 6, 4 * i, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_write(&core, 6, 4 * i, 4, (v & ~0xfULL) | 0xf));
        CHECK(apple_modern_pmgr_storage_core_read(&core, 6, 4 * i, 4, &v) && v == 0xf && !(v & 0x10));
    }
    CHECK(apple_modern_pmgr_storage_core_read(&core, 6, 8, 8, &v) && v == 0xf0000000fULL);
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 6, 20, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 6, 16, 8, &v));
    /* PMGR_SOC_PWRGATE full bank: +0x0/+0x40 RMW bit31; +0x60 is the bring-up probe. */
    CHECK(apple_modern_pmgr_storage_core_read(&core, PWRGATE_WINDOW, 0, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_write(&core, PWRGATE_WINDOW, 0, 4, v | 0x80000000u));
    CHECK(apple_modern_pmgr_storage_core_read(&core, PWRGATE_WINDOW, 0, 4, &v) && v == 0x80000000u);
    CHECK(apple_modern_pmgr_storage_core_read(&core, PWRGATE_WINDOW, 0x40, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_write(&core, PWRGATE_WINDOW, 0x40, 4, v | 0x80000000u));
    CHECK(apple_modern_pmgr_storage_core_read(&core, PWRGATE_WINDOW, 0x40, 4, &v) && v == 0x80000000u);
    CHECK(apple_modern_pmgr_storage_core_read(&core, PWRGATE_WINDOW, 0x60, 4, &v) && v == 0);
    /* PMGR_SOC_DPE: per channel read-modify-write setting bit 0 at +0x200, +0x0 and
     * +0x300 (channel 7: +0x200 and +0x300 of its 0x4000 base only). */
    CHECK(apple_modern_pmgr_storage_core_read(&core, 7, 0x200, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_write(&core, 7, 0x200, 4, v | 1));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 7, 0x200, 4, &v) && v == 1);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 7, 0, 4, &v) && v == 0);
    CHECK(apple_modern_pmgr_storage_core_read(&core, 7, 0x300, 4, &v) && v == 0);
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 7, 0x100, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 7, 0x204, 4, &v));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 7, 0x304, 4, &v) && apple_modern_pmgr_storage_core_read(&core, 7, 0x308, 4, &v) && apple_modern_pmgr_storage_core_read(&core, 7, 0x30c, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 7, 0x310, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 7, 0x200, 8, &v));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 14, 0, 4, &v) && apple_modern_pmgr_storage_core_read(&core, 14, 0x100, 4, &v));
    CHECK(!apple_modern_pmgr_storage_core_read(&core, 14, 0x200, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 14, 4, 4, &v));
    CHECK(apple_modern_pmgr_storage_core_read(&core, 16, 0x300, 4, &v) && apple_modern_pmgr_storage_core_read(&core, 16, 0x304, 4, &v) && apple_modern_pmgr_storage_core_read(&core, 16, 0x308, 4, &v) && apple_modern_pmgr_storage_core_read(&core, 16, 0x30c, 4, &v) && !apple_modern_pmgr_storage_core_read(&core, 16, 0x310, 4, &v));
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
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x18, 8, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x1c, 8, &v));
        /* The BWR interface (stateChange bit 3): read-modify-write of +0x20, setting then
         * clearing the record's bit (bit 7 as an example); +0x20 and +0x24 pair up as one
         * naturally aligned 8-byte access. */
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x20, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x20, 4, v | (1u << 7)));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x20, 4, &v) && v == 0x80);
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x20, 8, &v) && v == 0x300000080ULL);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x20, 4, 0x80 & ~(1u << 7)));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x20, 8, &v) && v == 0x300000000ULL);
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x2c, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x24, 8, &v));
        CHECK(!apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x2c, 4, 1));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x28, 8, &v));   /* runs past the end */
        /* The BOOST interface (ApplePMC::stateChange bit 1): read-modify-write of +0x28, setting
         * (enable) and then clearing (disable) the device's bit; here bit 5 as an example. */
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x28, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x28, 4, v | (1u << 5)));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x28, 4, &v) && v == 0x20);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC_WINDOW, 0x28, 4, v & ~(1u << 5)));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x28, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x24, 4, &v) && v == 3);   /* neighbour kept */
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC2_WINDOW, 4, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC2_WINDOW, 0, 8, &v));
        /* A neighbouring window (DPE channel 9, its +0x300 register) is separate storage. */
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW - 1, 0x300, 4, &v));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0, 4, &v) && v == 0xb);
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC_WINDOW, 0x24, 4, &v) && v == 3);
    }
    /* setTVMEnable(0xb, enable 0, wait 1): RMW +0x400 bit0, poll +0x7e0 bit1 clear.
     * Full-bank window also covers index-1 (+0x0/+0x3e0) used in complex bring-up. */
    {
        CHECK(plan.windows[TVM_WINDOW].address == UINT64_C(0x300760000));
        CHECK(apple_modern_pmgr_storage_core_read(&core, TVM_WINDOW, 0x400, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_write(&core, TVM_WINDOW, 0x400, 4, (v & ~1ULL) | 0));
        CHECK(apple_modern_pmgr_storage_core_read(&core, TVM_WINDOW, 0x7e0, 4, &v) && !(v & 2));
        CHECK(apple_modern_pmgr_storage_core_write(&core, TVM_WINDOW, 0x400, 4, 0xffffffffu));
        CHECK(apple_modern_pmgr_storage_core_write(&core, TVM_WINDOW, 0x400, 4, (0xffffffffu & ~1ULL) | 1));
        CHECK(apple_modern_pmgr_storage_core_read(&core, TVM_WINDOW, 0x400, 4, &v) && v == 0xffffffffu);
        CHECK(apple_modern_pmgr_storage_core_write(&core, TVM_WINDOW, 0x400, 4, 0));
        CHECK(apple_modern_pmgr_storage_core_write(&core, TVM_WINDOW, 0x7e0, 4, 2));
        CHECK(apple_modern_pmgr_storage_core_read(&core, TVM_WINDOW, 0x7e0, 4, &v) && v == 2);
        CHECK(apple_modern_pmgr_storage_core_write(&core, TVM_WINDOW, 0x7e0, 4, 0));
        /* Index 1 path (MEASURED start hang): +0x0/+0x3e0 */
        CHECK(apple_modern_pmgr_storage_core_read(&core, TVM_WINDOW, 0x0, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_read(&core, TVM_WINDOW, 0x3e0, 4, &v) && !(v & 2));
        CHECK(apple_modern_pmgr_storage_core_read(&core, TVM_WINDOW, 0, 8, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, TVM_WINDOW, 0x4000, 4, &v));
    }
    /* The second T8140 PS-write hook table: when the written PMGR_SOC register has reached its
     * target (flag 1) the hook writes PwrGate +0xc8c = 0 then +0xcd0 = 1 (flag 0: 3 and 0). */
    {
        CHECK(plan.windows[PWRGATE_WINDOW].address == UINT64_C(0x300724000));
        CHECK(apple_modern_pmgr_storage_core_write(&core, PWRGATE_WINDOW, 0xc8c, 4, 0));
        CHECK(apple_modern_pmgr_storage_core_write(&core, PWRGATE_WINDOW, 0xcd0, 4, 1));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PWRGATE_WINDOW, 0xcd0, 4, &v) && v == 1);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PWRGATE_WINDOW, 0x60, 4, 0)); /* bring-up offset */
        CHECK(apple_modern_pmgr_storage_core_read(&core, PWRGATE_WINDOW, 0x60, 4, &v) && v == 0);
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PWRGATE_WINDOW, 0x4000, 4, &v));
    }
    /* ApplePMC::stateChange, DVMR interface for one device (bit 3 of the state register as an
     * example): read +0xa4000, set the bit, write it back, poll +0xa4020 until bit 0 is
     * clear (it never is set here), read +0xa4000, write the population count to +0xa9c14. */
    {
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC3_WINDOW, 0, 4, &v) && v == 0);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC3_WINDOW, 0, 4, v | (1u << 3)));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC3_WINDOW, 0x20, 4, &v) && !(v & 1));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC3_WINDOW, 0, 4, &v) && v == 8);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC4_WINDOW, 0, 4, __builtin_popcount((unsigned)v)));
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC4_WINDOW, 0, 4, &v) && v == 1);
        /* The registers in between, the neighbours and the ends do not exist. */
        for (uint64_t off = 4; off < 0x24; off += 4) {
            CHECK(off == 0x20 || !apple_modern_pmgr_storage_core_read(&core, PMC3_WINDOW, off, 4, &v));
        }
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC3_WINDOW, 0x24, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC3_WINDOW, 0, 8, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC3_WINDOW, 0x20, 8, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC4_WINDOW, 4, 4, &v));
        CHECK(!apple_modern_pmgr_storage_core_read(&core, PMC4_WINDOW, 0, 8, &v));
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC3_WINDOW, 0x20, 4, 1));   /* a driver may set busy; the model keeps it */
        CHECK(apple_modern_pmgr_storage_core_read(&core, PMC3_WINDOW, 0x20, 4, &v) && v == 1);
        CHECK(apple_modern_pmgr_storage_core_write(&core, PMC3_WINDOW, 0x20, 4, 0));
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
