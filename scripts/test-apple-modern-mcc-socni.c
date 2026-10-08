/* Sparse SOCNI virtual channel and matched layout qualification.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-mcc-socni.h"
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
    AppleModernMCCSocniCore core = {.reset_value = UINT64_C(0xfedcba9876543210)};
    uint64_t value;
    unsigned total = 0;
    apple_modern_mcc_socni_core_reset(&core);
    for (unsigned bank = 0; bank < 3; bank++) {
        unsigned count = apple_modern_mcc_socni_counter_count(bank);
        CHECK(count == (bank == 0 ? 31 : bank == 1 ? 36 : 35));
        CHECK(apple_modern_mcc_socni_view_span(bank * 2) == count * 4);
        CHECK(apple_modern_mcc_socni_view_span(bank * 2 + 1) == count * 8);
        total += count;
        for (unsigned index = 0; index < count; index++) {
            CHECK(apple_modern_mcc_socni_core_read(&core, bank * 2, index * 4, 4, &value));
            CHECK(value == 0);
            CHECK(apple_modern_mcc_socni_core_event(&core, bank, index, 9));
            CHECK(apple_modern_mcc_socni_core_read(&core, bank * 2 + 1, index * 8, 8, &value));
            CHECK(value == core.reset_value);
        }
    }
    CHECK(total == 102 && core.reads == 204 && !core.writes && !core.event_updates);
    CHECK(!apple_modern_mcc_socni_counter_count(3));
    CHECK(!apple_modern_mcc_socni_view_span(6));
    /* Independent controls retain all 32 bits; only low two bits gate events. */
    for (unsigned bank = 0; bank < 3; bank++) {
        for (unsigned index = 0; index < apple_modern_mcc_socni_counter_count(bank); index++) {
            uint32_t control = UINT32_C(0x81a50003) | bank << 12 | index << 2;
            CHECK(apple_modern_mcc_socni_core_write(&core, bank * 2, index * 4, 4, control));
            CHECK(apple_modern_mcc_socni_core_read(&core, bank * 2, index * 4, 4, &value));
            CHECK(value == control);
            for (unsigned candidate = 0; candidate < apple_modern_mcc_socni_counter_count(bank); candidate++) {
                CHECK(apple_modern_mcc_socni_core_event(&core, bank, candidate, 17));
            }
            CHECK(apple_modern_mcc_socni_core_read(&core, bank * 2 + 1, index * 8, 8, &value));
            CHECK(value == core.reset_value + 17);
            CHECK(apple_modern_mcc_socni_core_write(&core, bank * 2, index * 4, 4, control & ~3U));
            CHECK(apple_modern_mcc_socni_core_event(&core, bank, index, 23));
            CHECK(core.values[bank][index] == core.reset_value + 17);
        }
        for (unsigned index = 0; index < apple_modern_mcc_socni_counter_count(bank); index++) {
            CHECK(core.values[bank][index] == core.reset_value + 17);
        }
        for (unsigned other = bank + 1; other < 3; other++) {
            for (unsigned index = 0; index < apple_modern_mcc_socni_counter_count(other); index++) {
                CHECK(core.values[other][index] == core.reset_value);
                CHECK(!core.controls[other][index]);
            }
        }
    }
    CHECK(core.event_updates == 102 && core.writes == 204 && core.reads == 408);
    uint64_t initial = core.values[0][0];
    for (unsigned low = 0; low < 3; low++) {
        CHECK(apple_modern_mcc_socni_core_write(&core, 0, 0, 4, UINT32_C(0xfffffffc) | low));
        CHECK(apple_modern_mcc_socni_core_event(&core, 0, 0, UINT64_MAX));
        CHECK(core.values[0][0] == initial && core.event_updates == 102);
    }
    CHECK(apple_modern_mcc_socni_core_write(&core, 0, 0, 4, UINT32_MAX));
    CHECK(apple_modern_mcc_socni_core_event(&core, 0, 0, UINT64_MAX));
    CHECK(core.values[0][0] == initial - 1 && core.event_updates == 103);
    CHECK(apple_modern_mcc_socni_core_event(&core, 0, 0, 0));
    CHECK(core.event_updates == 103);

    AppleModernMCCSocniCore before = core;
    value = UINT64_C(0x123456789abcdef0);
    CHECK(!apple_modern_mcc_socni_core_read(NULL, 0, 0, 4, &value));
    CHECK(!apple_modern_mcc_socni_core_read(&core, 6, 0, 4, &value));
    CHECK(!apple_modern_mcc_socni_core_read(&core, 0, 0, 4, NULL));
    CHECK(!apple_modern_mcc_socni_core_read(&core, 0, 0, 4, &core.values[0][0]));
    CHECK(!apple_modern_mcc_socni_core_write(NULL, 0, 0, 4, 1));
    CHECK(!apple_modern_mcc_socni_core_event(NULL, 0, 0, 1));
    CHECK(!apple_modern_mcc_socni_core_event(&core, 3, 0, 1));
    for (unsigned bank = 0; bank < 3; bank++) {
        unsigned count = apple_modern_mcc_socni_counter_count(bank);
        CHECK(!apple_modern_mcc_socni_core_event(&core, bank, count, 1));
        for (unsigned kind = 0; kind < 2; kind++) {
            unsigned view = bank * 2 + kind, width = kind ? 8 : 4;
            for (unsigned bad = 0; bad <= 16; bad++) {
                if (bad == width) { continue; }
                CHECK(!apple_modern_mcc_socni_core_read(&core, view, 0, bad, &value));
                CHECK(!apple_modern_mcc_socni_core_write(&core, view, 0, bad, 1));
            }
            CHECK(!apple_modern_mcc_socni_core_read(&core, view, count * width, width, &value));
            CHECK(!apple_modern_mcc_socni_core_read(&core, view, 1, width, &value));
            CHECK(!apple_modern_mcc_socni_core_read(&core, view, UINT64_MAX, width, &value));
            CHECK(!apple_modern_mcc_socni_core_write(&core, view, count * width, width, 1));
            CHECK(!apple_modern_mcc_socni_core_write(&core, view, 1, width, 1));
            CHECK(!apple_modern_mcc_socni_core_write(&core, view, UINT64_MAX, width, 1));
        }
        for (unsigned index = 0; index < count; index++) {
            CHECK(!apple_modern_mcc_socni_core_write(&core, bank * 2 + 1, index * 8, 8, 1));
        }
    }
    CHECK(value == UINT64_C(0x123456789abcdef0));
    CHECK(!memcmp(&core, &before, sizeof(core)));
    core.reads = core.writes = core.event_updates = UINT64_MAX;
    CHECK(apple_modern_mcc_socni_core_write(&core, 0, 0, 4, 3));
    CHECK(apple_modern_mcc_socni_core_event(&core, 0, 0, 1));
    CHECK(apple_modern_mcc_socni_core_read(&core, 1, 0, 8, &value));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX && core.event_updates == UINT64_MAX);
    apple_modern_mcc_socni_core_reset(&core);
    CHECK(!core.reads && !core.writes && !core.event_updates);
    for (unsigned bank = 0; bank < 3; bank++) {
        for (unsigned index = 0; index < apple_modern_mcc_socni_counter_count(bank); index++) {
            CHECK(!core.controls[bank][index]);
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
    AppleModernMCCSocniPlan plan;
    Error *error = NULL;
    const uint64_t dram = UINT64_C(0x10000000000), size = UINT64_C(8) << 30;
    const uint64_t bases[] = {UINT64_C(0x24f008000), UINT64_C(0x250008000), UINT64_C(0x251008000)};
    CHECK(apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    for (unsigned view = 0; view < 6; view++) {
        uint64_t address = bases[view / 2] + (view % 2 ? 0x4000 : 0);
        uint64_t span = apple_modern_mcc_socni_counter_count(view / 2) * (view % 2 ? 8 : 4);
        CHECK(plan.addresses[view] == address && plan.spans[view] == span);
        AppleModernAddressRange collision = {address + span - 1, 1};
        CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, &collision, 1, &plan, &error));
        clear_error(&error); CHECK(!plan.addresses[0] && !plan.spans[0]);
        CHECK(!apple_modern_mcc_socni_plan_build(blob, address, span, NULL, 0, &plan, &error));
        clear_error(&error);
        AppleModernAddressRange adjacent[] = {{address - 8, 8}, {address + span, 8}};
        CHECK(apple_modern_mcc_socni_plan_build(blob, dram, size, adjacent, 2, &plan, &error));
    }
    const char *names[] = {"compatible", "socni-reg-idx", "socni-count", "reg"};
    for (unsigned i = 0; i < 4; i++) {
        CHECK(apple_modern_adt_property(blob, "/arm-io/mcc", names[i], &property, &error));
        unsigned cases = i == 3 ? 6 : 1;
        for (unsigned j = 0; j < cases; j++) {
            uint8_t *byte = (uint8_t *)property.data + (i == 3 ? (3 + j / 2) * 16 + (j % 2) * 8 : 0);
            *byte ^= 1;
            CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 0, &plan, &error));
            clear_error(&error); CHECK(!plan.addresses[0]); *byte ^= 1;
        }
    }
    CHECK(apple_modern_adt_property(blob, "/arm-io", "ranges", &property, &error));
    CHECK(property.size >= 48);
    uint8_t saved[24]; memcpy(saved, property.data + 24, 24);
    memcpy((uint8_t *)property.data + 24, property.data, 24);
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data + 24, saved, 24);
    memcpy(saved, property.data, 24);
    ((uint8_t *)property.data)[8] ^= 1;
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, saved, 24);
    memset((uint8_t *)property.data + 16, 0xff, 8);
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, saved, 24);
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1];
    for (unsigned i = 0; i < APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1; i++) {
        exclusions[i] = (AppleModernAddressRange){UINT64_C(0x1000) + i * 8, 8};
    }
    CHECK(apple_modern_mcc_socni_plan_build(blob, dram, size, exclusions, APPLE_MODERN_MAX_BOARD_EXCLUSIONS, &plan, &error));
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, exclusions, APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1, &plan, &error)); clear_error(&error);
    AppleModernAddressRange wrap = {UINT64_MAX, 8}, empty = {0, 0};
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, &wrap, 1, &plan, &error)); clear_error(&error);
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, &empty, 1, &plan, &error)); clear_error(&error);
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 1, &plan, &error)); clear_error(&error);
    CHECK(!apple_modern_mcc_socni_plan_build(blob, UINT64_MAX, size, NULL, 0, &plan, &error)); clear_error(&error);
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, 0, NULL, 0, &plan, &error)); clear_error(&error);
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 0, NULL, &error)); clear_error(&error);
    uint8_t *tree_before = malloc(length); CHECK(tree_before); memcpy(tree_before, tree, length);
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 0, (AppleModernMCCSocniPlan *)(void *)tree, &error));
    clear_error(&error); CHECK(!memcmp(tree, tree_before, length));
    CHECK(!apple_modern_mcc_socni_plan_build(blob, dram, size, (AppleModernAddressRange *)(void *)&plan, 1, &plan, &error)); clear_error(&error);
    CHECK(apple_modern_mcc_socni_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    free(tree_before); free(tree);
    printf("{\"passed\":true,\"checks\":%u,\"firmware_executed\":false}\n", checks);
    return 0;
}
