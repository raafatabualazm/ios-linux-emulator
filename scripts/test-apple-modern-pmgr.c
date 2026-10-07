/* Production PMGR planning/power-cell gate with owned data; no Apple code runs.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-pmgr.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #x); exit(1); } } while (0)

typedef struct Fixture {
    uint8_t bytes[4096];
    size_t size, ranges, reg, groups, devices, compatible;
} Fixture;

static void put(uint8_t *p, uint64_t value, unsigned bytes)
{
    for (unsigned i = 0; i < bytes; i++) {
        p[i] = value >> (8 * i);
    }
}

static size_t property(Fixture *f, const char *name, const void *data, size_t size)
{
    uint8_t *p = f->bytes + f->size;
    size_t value = f->size + 36;
    CHECK(strlen(name) < 32 && f->size + 36 + size + 3 < sizeof(f->bytes));
    memcpy(p, name, strlen(name) + 1);
    put(p + 32, size, 4);
    memcpy(p + 36, data, size);
    f->size += 36 + ((size + 3) & ~(size_t)3);
    return value;
}

static void node(Fixture *f, unsigned props, unsigned children)
{
    put(f->bytes + f->size, props, 4);
    put(f->bytes + f->size + 4, children, 4);
    f->size += 8;
}

static Fixture fixture(void)
{
    Fixture f = {0};
    uint8_t range[24] = {0}, reg[32] = {0}, groups[24] = {0};
    uint8_t devices[4 * 48] = {0};
    put(range + 8, UINT64_C(0x210000000), 8);
    put(range + 16, UINT64_C(0x2f0000000), 8);
    put(reg, 0xf0700000, 8); put(reg + 8, 0x1000, 8);
    put(reg + 16, 0xf8280000, 8); put(reg + 24, 0x1000, 8);
    put(groups + 12, 1, 4);
    for (unsigned i = 0; i < 4; i++) {
        put(devices + i * 48 + 26, 0x69 + i, 2);
    }
    put(devices + 16, 0xc00, 3);
    put(devices + 48 + 16, 0xc08, 3);
    devices[96] = 0x10; /* virtual: deliberately invalid window/offset */
    devices[96 + 19] = 255;
    put(devices + 144 + 16, 0x58, 3); devices[144 + 19] = 1;
    node(&f, 1, 1); property(&f, "name", "device-tree", 12);
    node(&f, 2, 1); property(&f, "name", "arm-io", 7);
    f.ranges = property(&f, "ranges", range, sizeof(range));
    node(&f, 5, 0); property(&f, "name", "pmgr", 5);
    f.compatible = property(&f, "compatible", "pmgr1,t8140", 12);
    f.reg = property(&f, "reg", reg, sizeof(reg));
    f.groups = property(&f, "ps-groups", groups, sizeof(groups));
    f.devices = property(&f, "devices", devices, sizeof(devices));
    return f;
}

static AppleModernBlob blob(Fixture *f)
{
    return (AppleModernBlob){f->bytes, f->size};
}

static void reject(const char *name, Fixture *f, uint64_t dram,
                    uint64_t dram_size, const AppleModernAddressRange *ex,
                    size_t count)
{
    AppleModernPMGRPlan plan, zero = {0};
    Error *error = NULL;
    memset(&plan, 0x5a, sizeof(plan));
    CHECK(!apple_modern_pmgr_plan_build(blob(f), dram, dram_size, ex, count,
                                        &plan, &error));
    CHECK(error && !memcmp(&plan, &zero, sizeof(plan)));
    printf("REJECT %s: %s\n", name, error->message);
    error_free(error);
}
#define REJECT(n) reject(n, &f, UINT64_C(1) << 40, UINT64_C(8) << 30, NULL, 0)

static void cells_gate(const AppleModernPMGRPlan *plan)
{
    AppleModernPMGRCore core = {.plan = *plan};
    const AppleModernPMGRCell *cell = &plan->cells[0];
    const unsigned w = cell->window;
    const uint64_t off = cell->offset;
    apple_modern_pmgr_core_reset(&core);
    CHECK(!memcmp(&core.plan, plan, sizeof(*plan)));
    CHECK(apple_modern_pmgr_core_read(&core, w, off) == 0);
    /* Linux driver: request active, read actual active, then enable auto-PM. */
    apple_modern_pmgr_core_write(&core, w, off, 0xf);
    CHECK(apple_modern_pmgr_core_read(&core, w, off) == 0xff);
    apple_modern_pmgr_core_write(&core, w, off, 0x100000ff);
    CHECK(apple_modern_pmgr_core_read(&core, w, off) == 0x100000ff);
    CHECK(core.transitions == 1);
    /* Host cannot forge read-only actual nibble through a guest write. */
    apple_modern_pmgr_core_write(&core, w, off, 0xf0);
    CHECK(apple_modern_pmgr_core_read(&core, w, off) == 0);
    CHECK(core.transitions == 2);
    /* Hardware minimum prevents requests from taking it below retention. */
    apple_modern_pmgr_core_write(&core, w, off, 0x40000);
    CHECK(apple_modern_pmgr_core_read(&core, w, off) == 0x40040);
    /* Disable/reset controls are retained; they do not alter the target. */
    apple_modern_pmgr_core_write(&core, w, off, 0x8000040f);
    CHECK(apple_modern_pmgr_core_read(&core, w, off) == 0x800004ff);
    apple_modern_pmgr_core_write(&core, w, off, 0x4000000f);
    CHECK(apple_modern_pmgr_core_read(&core, w, off) == 0xff);
    for (unsigned target = 0; target < 16; target++) {
        for (unsigned minimum = 0; minimum < 16; minimum++) {
            uint32_t input = (minimum << 16) | target;
            apple_modern_pmgr_core_write(&core, w, off, input);
            uint32_t got = apple_modern_pmgr_core_read(&core, w, off);
            CHECK((got & 15) == target);
            CHECK(((got >> 16) & 15) == minimum);
            CHECK(((got >> 4) & 15) >= target);
            CHECK(((got >> 4) & 15) >= minimum);
            CHECK(((got >> 4) & 15) == target ||
                  ((got >> 4) & 15) == minimum);
        }
    }
    uint32_t before = apple_modern_pmgr_core_read(&core, w, off);
    apple_modern_pmgr_core_write(&core, w, off + 4, 0xffffffff);
    CHECK(apple_modern_pmgr_core_read(&core, w, off + 4) == 0);
    CHECK(apple_modern_pmgr_core_read(&core, w, off) == before);
    apple_modern_pmgr_core_write(&core, plan->window_count, off, 0xf);
    CHECK(apple_modern_pmgr_core_read(&core, plan->window_count, off) == 0);
    apple_modern_pmgr_core_write(&core, w, core.plan.windows[w].size, 0xf);
    CHECK(apple_modern_pmgr_core_read(&core, w,
                core.plan.windows[w].size) == 0);
    apple_modern_pmgr_core_write(&core, w, off + 1, 0xf);
    CHECK(apple_modern_pmgr_core_read(&core, w, off + 1) == 0);
    CHECK(core.unknown_reads == 4 && core.unknown_writes == 4);
    CHECK(core.reads > core.unknown_reads && core.writes > core.unknown_writes);
    core.writes = UINT64_MAX;
    apple_modern_pmgr_core_write(&core, w, off, 0);
    CHECK(core.writes == UINT64_MAX);
    apple_modern_pmgr_core_reset(&core);
    CHECK(!memcmp(&core.plan, plan, sizeof(*plan)));
    CHECK(!core.reads && !core.writes && !core.unknown_reads &&
          !core.unknown_writes && !core.transitions);
    for (unsigned i = 0; i < plan->cell_count; i++) {
        CHECK(core.values[i] == 0);
    }
}

int main(int argc, char **argv)
{
    Fixture f = fixture();
    AppleModernPMGRPlan plan;
    Error *error = NULL;
    uint8_t before[sizeof(f.bytes)];
    memcpy(before, f.bytes, sizeof(before));
    bool built = apple_modern_pmgr_plan_build(blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, NULL, 0, &plan, &error);
    if (!built && error) {
        fprintf(stderr, "Fixture plan: %s\n", error->message);
    }
    CHECK(built);
    CHECK(!error && plan.window_count == 2 && plan.cell_count == 3 &&
          plan.virtual_count == 1);
    CHECK(plan.windows[0].base == UINT64_C(0x300700000));
    CHECK(plan.windows[1].base == UINT64_C(0x308280000));
    CHECK(plan.cells[0].id == 0x69 && plan.cells[0].offset == 0xc00);
    CHECK(!memcmp(before, f.bytes, sizeof(before)));
    cells_gate(&plan);
    f = fixture(); put(f.bytes + f.reg + 8, 3, 8); REJECT("short window");
    f = fixture(); put(f.bytes + f.reg + 8, 0x100001, 8); REJECT("window budget");
    f = fixture(); put(f.bytes + f.reg, UINT64_MAX - 8, 8); REJECT("wrapping child");
    f = fixture(); put(f.bytes + f.ranges + 8, UINT64_MAX - 8, 8); REJECT("wrapping bus");
    f = fixture(); put(f.bytes + f.reg + 16, 0xf0700001, 8); REJECT("overlapping windows");
    f = fixture(); put(f.bytes + f.groups + 12, 2, 4); REJECT("group index");
    f = fixture(); put(f.bytes + f.groups + 4, 0x1000, 4); REJECT("group offset");
    f = fixture(); put(f.bytes + f.groups + 8, 1, 4); REJECT("unsupported group flags");
    f = fixture(); put(f.bytes + f.devices + 16, 0xc04, 3); REJECT("cell alignment");
    f = fixture(); put(f.bytes + f.devices + 16, 0x1000, 3); REJECT("cell bounds");
    f = fixture(); put(f.bytes + f.devices + 48 + 16, 0xc00, 3); REJECT("duplicate cell");
    f = fixture(); put(f.bytes + f.devices + 48 + 26, 0x69, 2); REJECT("duplicate id");
    f = fixture(); put(f.bytes + f.devices + 26, 0, 2); REJECT("zero id");
    f = fixture(); f.bytes[f.devices + 19] = 2; REJECT("device group");
    f = fixture(); f.bytes[f.compatible + 9] = '1'; REJECT("wrong SoC");
    f = fixture(); put(f.bytes + f.devices - 4, 193, 4); REJECT("record length");
    f = fixture(); put(f.bytes + f.groups - 4, 25, 4); REJECT("group length");
    f = fixture(); put(f.bytes + f.reg - 4, 33, 4); REJECT("reg length");
    f = fixture(); reject("DRAM overlap", &f, 0x300700000, 0x1000, NULL, 0);
    AppleModernAddressRange ex = {0x300700c07, 1};
    reject("one-byte device overlap", &f, UINT64_C(1) << 40,
           UINT64_C(8) << 30, &ex, 1);
    reject("missing exclusions", &f, UINT64_C(1) << 40,
           UINT64_C(8) << 30, NULL, 1);
    ex = (AppleModernAddressRange){0x300700100, 0x100};
    CHECK(apple_modern_pmgr_plan_build(blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, &ex, 1, &plan, &error));
    CHECK(!error); /* Another device in the container's hole is allowed. */
    /* Input alias is rejected without modifying even the output memory. */
    CHECK(!apple_modern_pmgr_plan_build(blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, NULL, 0, (AppleModernPMGRPlan *)f.bytes, &error));
    CHECK(error && !memcmp(before, f.bytes, sizeof(before)));
    error_free(error); error = NULL;
    if (argc == 2) {
        FILE *fp = fopen(argv[1], "rb");
        CHECK(fp && !fseek(fp, 0, SEEK_END));
        long size = ftell(fp);
        CHECK(size > 0 && size < 16 * 1024 * 1024 && !fseek(fp, 0, SEEK_SET));
        uint8_t *data = malloc(size);
        CHECK(data && fread(data, 1, size, fp) == (size_t)size);
        CHECK(!fclose(fp));
        CHECK(apple_modern_pmgr_plan_build((AppleModernBlob){data, size},
                 UINT64_C(1) << 40, UINT64_C(8) << 30, NULL, 0, &plan, &error));
        CHECK(!error && plan.window_count == 2 && plan.cell_count == 138 &&
              plan.virtual_count == 158);
        bool sep = false;
        for (unsigned i = 0; i < plan.cell_count; i++) {
            if (plan.cells[i].id == 0x69) {
                const AppleModernPMGRCell *c = &plan.cells[i];
                CHECK(plan.windows[c->window].base + c->offset ==
                      UINT64_C(0x300700c00));
                sep = true;
            }
        }
        CHECK(sep);
        printf("ACTUAL windows=%u hardware_cells=%u virtual_domains=%u\n",
               plan.window_count, plan.cell_count, plan.virtual_count);
        cells_gate(&plan);
        free(data);
    }
    printf("PASS %u PMGR checks\n", checks);
    return 0;
}
