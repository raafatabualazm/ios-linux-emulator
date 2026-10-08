/* Sparse AMCC virtual event-channel and geometry qualification.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-mcc-perf.h"
static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

static void clear_error(Error **error)
{
    CHECK(*error != NULL);
    error_free(*error);
    *error = NULL;
}

int main(int argc, char **argv)
{
    AppleModernMCCPerfCore core = {.reset_value = UINT64_C(0xfedcba9876543210)};
    uint64_t value;
    apple_modern_mcc_perf_core_reset(&core);
    for (unsigned bank = 0; bank < 3; bank++) {
        CHECK(apple_modern_mcc_perf_core_read(&core, bank * 2, 0, &value));
        CHECK(value == 0);
        for (unsigned index = 0; index < 8; index++) {
            CHECK(apple_modern_mcc_perf_core_event(&core, bank, index, 9));
            CHECK(apple_modern_mcc_perf_core_read(&core, bank * 2 + 1,
                                                  index * 8, &value));
            CHECK(value == core.reset_value);
        }
    }
    CHECK(core.reads == 27 && !core.writes && !core.event_updates);
    /* One enabled channel at a time: other counters and banks stay still. */
    for (unsigned bank = 0; bank < 3; bank++) {
        for (unsigned index = 0; index < 8; index++) {
            uint64_t mask = UINT64_C(1) << index;
            uint64_t control = UINT64_C(0xa5f0dead00000000) | mask;
            CHECK(apple_modern_mcc_perf_core_write(&core, bank * 2, 0, control));
            CHECK(apple_modern_mcc_perf_core_read(&core, bank * 2, 0, &value));
            CHECK(value == control);
            for (unsigned candidate = 0; candidate < 8; candidate++) {
                CHECK(apple_modern_mcc_perf_core_event(&core, bank, candidate, 17));
            }
            CHECK(apple_modern_mcc_perf_core_read(&core, bank * 2 + 1,
                                                  index * 8, &value));
            CHECK(value == core.reset_value + 17);
            CHECK(apple_modern_mcc_perf_core_write(&core, bank * 2, 0, 0));
            CHECK(apple_modern_mcc_perf_core_event(&core, bank, index, 23));
            CHECK(core.values[bank][index] == core.reset_value + 17);
        }
        for (unsigned index = 0; index < 8; index++) {
            CHECK(core.values[bank][index] == core.reset_value + 17);
        }
        for (unsigned other = bank + 1; other < 3; other++) {
            for (unsigned index = 0; index < 8; index++) {
                CHECK(core.values[other][index] == core.reset_value);
            }
        }
    }
    CHECK(core.event_updates == 24 && core.writes == 48 && core.reads == 75);
    /* Full-width modulo arithmetic, zero amounts and unrelated control bits. */
    CHECK(apple_modern_mcc_perf_core_write(&core, 2, 0, UINT64_C(0xffffffffffffff01)));
    uint64_t initial = core.values[1][0];
    CHECK(apple_modern_mcc_perf_core_event(&core, 1, 0, UINT64_MAX));
    CHECK(core.values[1][0] == initial - 1);
    CHECK(apple_modern_mcc_perf_core_event(&core, 1, 0, 0));
    CHECK(core.event_updates == 25);
    CHECK(apple_modern_mcc_perf_core_write(&core, 2, 0, UINT64_C(0xffffffffffffff00)));
    CHECK(apple_modern_mcc_perf_core_event(&core, 1, 0, UINT64_MAX));
    CHECK(core.values[1][0] == initial - 1 && core.event_updates == 25);

    AppleModernMCCPerfCore before = core;
    value = UINT64_C(0x123456789abcdef0);
    CHECK(!apple_modern_mcc_perf_core_read(NULL, 0, 0, &value));
    CHECK(!apple_modern_mcc_perf_core_read(&core, 6, 0, &value));
    CHECK(!apple_modern_mcc_perf_core_read(&core, 0, 8, &value));
    CHECK(!apple_modern_mcc_perf_core_read(&core, 1, 64, &value));
    CHECK(!apple_modern_mcc_perf_core_read(&core, 1, 4, &value));
    CHECK(!apple_modern_mcc_perf_core_read(&core, 1, UINT64_MAX, &value));
    CHECK(!apple_modern_mcc_perf_core_read(&core, 0, 0, NULL));
    CHECK(!apple_modern_mcc_perf_core_read(&core, 0, 0, &core.controls[0]));
    CHECK(!apple_modern_mcc_perf_core_write(NULL, 0, 0, 1));
    CHECK(!apple_modern_mcc_perf_core_write(&core, 6, 0, 1));
    CHECK(!apple_modern_mcc_perf_core_write(&core, 0, 8, 1));
    CHECK(!apple_modern_mcc_perf_core_write(&core, 1, 0, 1));
    CHECK(!apple_modern_mcc_perf_core_write(&core, 0, UINT64_MAX, 1));
    CHECK(!apple_modern_mcc_perf_core_event(NULL, 0, 0, 1));
    CHECK(!apple_modern_mcc_perf_core_event(&core, 3, 0, 1));
    CHECK(!apple_modern_mcc_perf_core_event(&core, 0, 8, 1));
    CHECK(value == UINT64_C(0x123456789abcdef0));
    CHECK(!memcmp(&core, &before, sizeof(core)));
    core.reads = core.writes = core.event_updates = UINT64_MAX;
    CHECK(apple_modern_mcc_perf_core_write(&core, 0, 0, 1));
    CHECK(apple_modern_mcc_perf_core_event(&core, 0, 0, 1));
    CHECK(apple_modern_mcc_perf_core_read(&core, 1, 0, &value));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX &&
          core.event_updates == UINT64_MAX);
    apple_modern_mcc_perf_core_reset(&core);
    CHECK(!core.reads && !core.writes && !core.event_updates);
    for (unsigned bank = 0; bank < 3; bank++) {
        CHECK(!core.controls[bank]);
        for (unsigned index = 0; index < 8; index++) {
            CHECK(core.values[bank][index] == core.reset_value);
        }
    }

    CHECK(argc == 2);
    FILE *file = fopen(argv[1], "rb"); CHECK(file);
    CHECK(!fseek(file, 0, SEEK_END)); long length = ftell(file);
    CHECK(length > 0 && length < 1 << 20); rewind(file);
    uint8_t *tree = malloc(length); CHECK(tree);
    CHECK(fread(tree, 1, length, file) == (size_t)length); fclose(file);
    AppleModernBlob blob = {tree, length}, property;
    AppleModernMCCPerfPlan plan;
    Error *error = NULL;
    const uint64_t dram = UINT64_C(0x10000000000), size = UINT64_C(8) << 30;
    CHECK(apple_modern_mcc_perf_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    for (unsigned view = 0; view < 6; view++) {
        uint64_t address = UINT64_C(0x220028000) +
            (uint64_t)(view / 2) * 0x40000 + (view % 2 ? 0x1000 : 0);
        uint64_t span = view % 2 ? 64 : 8;
        CHECK(plan.addresses[view] == address);
        AppleModernAddressRange collision = {address + span - 1, 1};
        CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size,
              &collision, 1, &plan, &error));
        clear_error(&error); CHECK(!plan.addresses[0]);
        CHECK(!apple_modern_mcc_perf_plan_build(blob, address, span,
              NULL, 0, &plan, &error));
        clear_error(&error); CHECK(!plan.addresses[0]);
        AppleModernAddressRange adjacent[] = {{address - 8, 8}, {address + span, 8}};
        CHECK(apple_modern_mcc_perf_plan_build(blob, dram, size,
              adjacent, 2, &plan, &error));
    }
    const char *names[] = {"compatible", "amcc-reg-idx", "dcs-count-per-amcc", "amcc-count", "reg"};
    for (unsigned i = 0; i < 5; i++) {
        CHECK(apple_modern_adt_property(blob, "/arm-io/mcc", names[i], &property, &error));
        uint8_t *byte = (uint8_t *)property.data + (i == 4 ? 2 * 16 : 0);
        *byte ^= 1;
        CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, NULL, 0, &plan, &error));
        clear_error(&error); CHECK(!plan.addresses[0]); *byte ^= 1;
    }
    CHECK(apple_modern_adt_property(blob, "/arm-io", "ranges", &property, &error));
    CHECK(property.size >= 48);
    uint8_t saved[24]; memcpy(saved, property.data + 24, 24);
    memcpy((uint8_t *)property.data + 24, property.data, 24);
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data + 24, saved, 24);
    memcpy(saved, property.data, 24);
    memset((uint8_t *)property.data + 16, 0xff, 8);
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, saved, 24);
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1];
    for (unsigned i = 0; i < APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1; i++) {
        exclusions[i] = (AppleModernAddressRange){UINT64_C(0x1000) + i * 8, 8};
    }
    CHECK(apple_modern_mcc_perf_plan_build(blob, dram, size, exclusions,
          APPLE_MODERN_MAX_BOARD_EXCLUSIONS, &plan, &error));
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, exclusions,
          APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1, &plan, &error));
    clear_error(&error);
    AppleModernAddressRange wrap = {UINT64_MAX, 8}, empty = {0, 0};
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, &wrap, 1, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, &empty, 1, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, NULL, 1, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_perf_plan_build(blob, UINT64_MAX, size, NULL, 0, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, 0, NULL, 0, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, NULL, 0, NULL, &error));
    clear_error(&error);
    uint8_t *tree_before = malloc(length); CHECK(tree_before);
    memcpy(tree_before, tree, length);
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size, NULL, 0,
          (AppleModernMCCPerfPlan *)(void *)tree, &error));
    clear_error(&error); CHECK(!memcmp(tree, tree_before, length));
    CHECK(!apple_modern_mcc_perf_plan_build(blob, dram, size,
          (AppleModernAddressRange *)(void *)&plan, 1, &plan, &error));
    clear_error(&error);
    CHECK(apple_modern_mcc_perf_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    free(tree_before); free(tree);
    printf("{\"passed\":true,\"checks\":%u,\"firmware_executed\":false}\n", checks);
    return 0;
}
