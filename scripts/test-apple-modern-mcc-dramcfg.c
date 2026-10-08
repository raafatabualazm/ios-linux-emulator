/* Owned sparse register state, reset and matched-layout qualification.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-mcc-dramcfg.h"
static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

int main(int argc, char **argv)
{
    AppleModernMCCDRAMCFGCore core = {.reset_value = 0x5a5a1234};
    uint32_t value = 0;
    apple_modern_mcc_dramcfg_core_reset(&core);
    for (unsigned bank = 0; bank < 4; bank++) {
        CHECK(apple_modern_mcc_dramcfg_core_read(&core, bank, 0, &value));
        CHECK(value == core.reset_value);
        for (unsigned bit = 0; bit < 32; bit++) {
            uint32_t word = UINT32_C(1) << bit;
            CHECK(apple_modern_mcc_dramcfg_core_write(&core, bank, 0, word));
            CHECK(apple_modern_mcc_dramcfg_core_read(&core, bank, 0, &value));
            CHECK(value == word);
        }
    }
    CHECK(core.reads == 132 && core.writes == 128);
    CHECK(core.values[0] == 0x80000000 && core.values[3] == 0x80000000);
    CHECK(apple_modern_mcc_dramcfg_core_write(&core, 2, 0, 0xabcdef12));
    CHECK(core.values[0] == 0x80000000 && core.values[2] == 0xabcdef12);
    AppleModernMCCDRAMCFGCore before = core;
    value = 0xfeed;
    CHECK(!apple_modern_mcc_dramcfg_core_read(&core, 4, 0, &value));
    CHECK(!apple_modern_mcc_dramcfg_core_read(&core, 0, 4, &value));
    CHECK(!apple_modern_mcc_dramcfg_core_read(&core, 0, UINT64_MAX, &value));
    CHECK(!apple_modern_mcc_dramcfg_core_read(&core, 0, 0, NULL));
    CHECK(!apple_modern_mcc_dramcfg_core_read(NULL, 0, 0, &value));
    CHECK(!apple_modern_mcc_dramcfg_core_read(&core, 0, 0, &core.values[0]));
    CHECK(value == 0xfeed && !memcmp(&core, &before, sizeof(core)));
    CHECK(!apple_modern_mcc_dramcfg_core_write(&core, 4, 0, 0));
    CHECK(!apple_modern_mcc_dramcfg_core_write(&core, 0, 1, 0));
    CHECK(!apple_modern_mcc_dramcfg_core_write(NULL, 0, 0, 0));
    CHECK(!memcmp(&core, &before, sizeof(core)));
    core.reads = core.writes = UINT64_MAX;
    CHECK(apple_modern_mcc_dramcfg_core_read(&core, 0, 0, &value));
    CHECK(apple_modern_mcc_dramcfg_core_write(&core, 0, 0, 1));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX);
    apple_modern_mcc_dramcfg_core_reset(&core);
    CHECK(!core.reads && !core.writes);
    for (unsigned i = 0; i < 4; i++) {
        CHECK(core.values[i] == core.reset_value);
    }

    CHECK(argc == 2);
    FILE *file = fopen(argv[1], "rb"); CHECK(file);
    CHECK(!fseek(file, 0, SEEK_END)); long length = ftell(file);
    CHECK(length > 0 && length < 1 << 20); rewind(file);
    uint8_t *tree = malloc(length); CHECK(tree);
    CHECK(fread(tree, 1, length, file) == (size_t)length); fclose(file);
    AppleModernBlob blob = {tree, length}, property;
    AppleModernMCCDRAMCFGPlan plan;
    Error *error = NULL;
    const uint64_t dram = UINT64_C(0x10000000000), size = UINT64_C(8) << 30;
    CHECK(apple_modern_mcc_dramcfg_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    for (unsigned i = 0; i < 4; i++) {
        CHECK(plan.addresses[i] == UINT64_C(0x220401d48) + (uint64_t)i * 0x200000);
    }
    for (unsigned i = 0; i < 4; i++) {
        AppleModernAddressRange collision = {plan.addresses[i], 4};
        CHECK(!apple_modern_mcc_dramcfg_plan_build(blob, dram, size,
              &collision, 1, &plan, &error));
        CHECK(error && !plan.addresses[0]); error_free(error); error = NULL;
        CHECK(apple_modern_mcc_dramcfg_plan_build(blob, dram, size, NULL, 0, &plan, &error));
        AppleModernAddressRange adjacent[] = {
            {plan.addresses[i] - 4, 4}, {plan.addresses[i] + 4, 4}};
        CHECK(apple_modern_mcc_dramcfg_plan_build(blob, dram, size,
              adjacent, 2, &plan, &error));
    }
    const char *names[] = {"compatible", "dcs-reg-idx", "dcs-count-per-amcc", "amcc-count", "reg"};
    for (unsigned i = 0; i < 5; i++) {
        CHECK(apple_modern_adt_property(blob, "/arm-io/mcc", names[i], &property, &error));
        size_t offset = i == 4 ? 8 * 16 : 0;
        uint8_t *byte = (uint8_t *)property.data + offset; *byte ^= 1;
        CHECK(!apple_modern_mcc_dramcfg_plan_build(blob, dram, size, NULL, 0, &plan, &error));
        CHECK(error && !plan.addresses[0]); error_free(error); error = NULL; *byte ^= 1;
    }
    CHECK(apple_modern_adt_property(blob, "/arm-io", "ranges", &property, &error));
    uint8_t *parent = (uint8_t *)property.data + 8; *parent ^= 1;
    CHECK(!apple_modern_mcc_dramcfg_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(error && !plan.addresses[0]); error_free(error); error = NULL; *parent ^= 1;
    AppleModernAddressRange wrap = {UINT64_MAX, 4};
    CHECK(!apple_modern_mcc_dramcfg_plan_build(blob, dram, size, &wrap, 1, &plan, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_dramcfg_plan_build(blob, dram, size, NULL, 1, &plan, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_dramcfg_plan_build(blob, UINT64_MAX, size, NULL, 0, &plan, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_dramcfg_plan_build(blob, UINT64_C(0x220400000), 0x8000,
                                             NULL, 0, &plan, &error));
    CHECK(error && !plan.addresses[0]); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_dramcfg_plan_build(blob, dram, size, NULL, 0,
                   (AppleModernMCCDRAMCFGPlan *)(void *)tree, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(apple_modern_mcc_dramcfg_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    free(tree);
    printf("{\"passed\":true,\"checks\":%u,\"firmware_executed\":false}\n", checks);
    return 0;
}
