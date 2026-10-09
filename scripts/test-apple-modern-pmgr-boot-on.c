/* PMGR boot-on reset profile gate against the real stock iPhone17,3 ADT.
 * No guest code runs.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-pmgr.h"

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

static int strcasecmp_local_placeholder(const char *a, const char *b)
{
    for (;; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'a' && x <= 'z') { x -= 32; }
        if (y >= 'a' && y <= 'z') { y -= 32; }
        if (x != y) { return x < y ? -1 : 1; }
        if (!x) { return 0; }
    }
}

static uint32_t cell_value(AppleModernPMGRCore *core, unsigned cell)
{
    return apple_modern_pmgr_core_read(core, core->plan.cells[cell].window,
                                       core->plan.cells[cell].offset);
}

int main(int argc, char **argv)
{
    static AppleModernPMGRPlan stock_plan, plan, backup;
    static AppleModernPMGRCore core;
    AppleModernBlob dtree, devices;
    Error *error = NULL;
    size_t count;
    const char *const *profile;
    unsigned expected_on = 0;
    CHECK(argc == 2);
    dtree = load(argv[1]);
    CHECK(apple_modern_pmgr_plan_build(dtree, UINT64_C(1) << 40, UINT64_C(8) << 30,
                                      NULL, 0, &stock_plan, &error));
    CHECK(stock_plan.cell_count == 138 && stock_plan.virtual_count == 158);
    for (unsigned i = 0; i < stock_plan.cell_count; i++) {
        CHECK(!stock_plan.boot_on[i]);
    }
    plan = stock_plan;
    /* Default board: every cell resets power-gated, exactly as before. */
    core.plan = plan;
    apple_modern_pmgr_core_reset(&core);
    for (unsigned i = 0; i < core.plan.cell_count; i++) {
        CHECK(cell_value(&core, i) == 0);
    }

    CHECK(!apple_modern_pmgr_boot_on_profile(NULL, &count) && !count);
    count = 9;
    CHECK(!apple_modern_pmgr_boot_on_profile("J700", &count) && !count);
    CHECK(!apple_modern_pmgr_boot_on_profile("", &count) && !count);
    profile = apple_modern_pmgr_boot_on_profile("j700", &count);
    CHECK(profile && count == 25);
    CHECK(apple_modern_pmgr_plan_set_boot_on(dtree, &plan, profile, count, &error));
    CHECK(!error);

    /* Independent oracle: decode the devices table here and compare. */
    CHECK(apple_modern_adt_property(dtree, "/arm-io/pmgr", "devices", &devices, &error));
    CHECK(devices.size == 296 * 48);
    for (unsigned c = 0; c < plan.cell_count; c++) {
        unsigned id = plan.cells[c].id, matched = 0;
        char name[17] = {0};
        for (size_t i = 0; i < devices.size; i += 48) {
            const uint8_t *r = devices.data + i;
            if ((unsigned)(r[26] | r[27] << 8) == id) {
                memcpy(name, r + 32, 16);
                matched++;
            }
        }
        CHECK(matched == 1);
        bool listed = false;
        for (size_t n = 0; n < count; n++) {
            listed |= !strcasecmp_local_placeholder(name, profile[n]);
        }
        CHECK(plan.boot_on[c] == listed);
        expected_on += listed;
    }
    CHECK(expected_on == 25);

    core.plan = plan;
    apple_modern_pmgr_core_reset(&core);
    for (unsigned i = 0; i < core.plan.cell_count; i++) {
        CHECK(cell_value(&core, i) == (plan.boot_on[i] ? APPLE_MODERN_PMGR_ACTIVE : 0));
    }
    /* Reads are not transitions; the counters restart at reset. */
    CHECK(core.transitions == 0 && core.writes == 0);
    /* A driver can still power an on-domain down and back, and reset restores it. */
    for (unsigned i = 0; i < core.plan.cell_count; i++) {
        if (plan.boot_on[i]) {
            apple_modern_pmgr_core_write(&core, core.plan.cells[i].window,
                                         core.plan.cells[i].offset, 0);
            CHECK(cell_value(&core, i) == 0);
            apple_modern_pmgr_core_write(&core, core.plan.cells[i].window,
                                         core.plan.cells[i].offset, 0xf);
            CHECK(cell_value(&core, i) == 0xff);
            apple_modern_pmgr_core_write(&core, core.plan.cells[i].window,
                                         core.plan.cells[i].offset, 0);
            break;
        }
    }
    CHECK(core.transitions == 3 && core.writes == 3);
    apple_modern_pmgr_core_reset(&core);
    for (unsigned i = 0; i < core.plan.cell_count; i++) {
        CHECK(cell_value(&core, i) == (plan.boot_on[i] ? APPLE_MODERN_PMGR_ACTIVE : 0));
    }

    /* Rejections leave the plan byte-identical. */
    backup = plan;
    {
        const char *const unknown[] = {"SEP", "NOT_A_DOMAIN"};
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, unknown, 2, &error));
        clear_error(&error);
        CHECK(!memcmp(&plan, &backup, sizeof(plan)));
        const char *const dup[] = {"AIC", "aic"};
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, dup, 2, &error));
        clear_error(&error);
        const char *const empty[] = {""};
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, empty, 1, &error));
        clear_error(&error);
        const char *const nullname[] = {NULL};
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, nullname, 1, &error));
        clear_error(&error);
        const char *const prefix[] = {"SEP_A"};   /* prefix of SEP_AON, not a name */
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, prefix, 1, &error));
        clear_error(&error);
        const char *const longer[] = {"SEP_AON_EXTRA_LONG_NAME_X"};
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, longer, 1, &error));
        clear_error(&error);
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, NULL, 1, &error));
        clear_error(&error);
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, NULL, profile, count, &error));
        clear_error(&error);
        CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, profile,
                                                  APPLE_MODERN_PMGR_MAX_CELLS + 1, &error));
        clear_error(&error);
        CHECK(!memcmp(&plan, &backup, sizeof(plan)));
    }
    /* A virtual domain has no cell and is refused by name. */
    for (size_t i = 0; i < devices.size; i += 48) {
        if (devices.data[i] & 0x10) {
            char name[17] = {0};
            const char *list[1] = {name};
            memcpy(name, devices.data + i + 32, 16);
            if (!name[0]) {
                continue;
            }
            CHECK(!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, list, 1, &error));
            clear_error(&error);
            CHECK(!memcmp(&plan, &backup, sizeof(plan)));
            break;
        }
    }
    /* An empty request clears the profile and is valid. */
    CHECK(apple_modern_pmgr_plan_set_boot_on(dtree, &plan, NULL, 0, &error));
    for (unsigned i = 0; i < plan.cell_count; i++) {
        CHECK(!plan.boot_on[i]);
    }
    /* The plan must not alias the device tree. */
    CHECK(!apple_modern_pmgr_plan_set_boot_on((AppleModernBlob){(const uint8_t *)&plan,
          sizeof(plan)}, &plan, profile, count, &error));
    clear_error(&error);
    free((void *)dtree.data);
    printf("PASS %u PMGR boot-on checks; no guest writes or execution\n", checks);
    return 0;
}
