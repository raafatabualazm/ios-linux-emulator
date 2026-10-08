/* Ordinary DSID quota storage and matched sparse layout qualification.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-mcc-quota.h"
static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

static uint32_t pattern(unsigned plane, unsigned group)
{
    return UINT32_C(0xa5000000) | plane << 16 | group << 8 | (31 - group);
}

int main(int argc, char **argv)
{
    AppleModernMCCQuotaCore core = {.reset_value = 0x5a5a1234};
    uint32_t value = 0;
    apple_modern_mcc_quota_core_reset(&core);
    for (unsigned plane = 0; plane < 4; plane++) {
        for (unsigned group = 0; group < 32; group++) {
            CHECK(apple_modern_mcc_quota_core_read(&core, plane, group * 4, &value));
            CHECK(value == core.reset_value);
            CHECK(apple_modern_mcc_quota_core_write(&core, plane, group * 4,
                                                   pattern(plane, group)));
        }
    }
    for (unsigned plane = 0; plane < 4; plane++) {
        for (unsigned group = 0; group < 32; group++) {
            CHECK(apple_modern_mcc_quota_core_read(&core, plane, group * 4, &value));
            CHECK(value == pattern(plane, group));
        }
    }
    CHECK(core.reads == 256 && core.writes == 128 && !core.broadcast_writes);
    for (unsigned bit = 0; bit < 32; bit++) {
        uint32_t word = UINT32_C(1) << bit;
        CHECK(apple_modern_mcc_quota_core_write(&core, 4, 11 * 4, word));
        for (unsigned plane = 0; plane < 4; plane++) {
            CHECK(apple_modern_mcc_quota_core_read(&core, plane, 11 * 4, &value));
            CHECK(value == word);
            CHECK(core.values[plane][10] == pattern(plane, 10));
            CHECK(core.values[plane][12] == pattern(plane, 12));
        }
    }
    CHECK(core.reads == 384 && core.writes == 160 && core.broadcast_writes == 32);
    CHECK(apple_modern_mcc_quota_core_write(&core, 2, 11 * 4, 0xfedcba98));
    CHECK(core.values[2][11] == 0xfedcba98 && core.values[0][11] == 0x80000000);
    for (unsigned group = 0; group < 32; group++) {
        uint32_t word = 0xde000080 | group;
        CHECK(apple_modern_mcc_quota_core_write(&core, 4, group * 4, word));
        for (unsigned plane = 0; plane < 4; plane++) {
            CHECK(apple_modern_mcc_quota_core_read(&core, plane, group * 4, &value));
            CHECK(value == word);
        }
    }
    AppleModernMCCQuotaCore before = core;
    value = 0xfeed;
    CHECK(!apple_modern_mcc_quota_core_read(&core, 4, 0, &value));
    CHECK(!apple_modern_mcc_quota_core_read(&core, 5, 0, &value));
    CHECK(!apple_modern_mcc_quota_core_read(&core, 0, 128, &value));
    CHECK(!apple_modern_mcc_quota_core_read(&core, 0, 1, &value));
    CHECK(!apple_modern_mcc_quota_core_read(&core, 0, UINT64_MAX, &value));
    CHECK(!apple_modern_mcc_quota_core_read(&core, 0, 0, NULL));
    CHECK(!apple_modern_mcc_quota_core_read(NULL, 0, 0, &value));
    CHECK(!apple_modern_mcc_quota_core_read(&core, 0, 0, &core.values[0][0]));
    CHECK(value == 0xfeed && !memcmp(&core, &before, sizeof(core)));
    CHECK(!apple_modern_mcc_quota_core_write(&core, 5, 0, 0));
    CHECK(!apple_modern_mcc_quota_core_write(&core, 0, 128, 0));
    CHECK(!apple_modern_mcc_quota_core_write(&core, 4, 129, 0));
    CHECK(!apple_modern_mcc_quota_core_write(&core, 0, UINT64_MAX, 0));
    CHECK(!apple_modern_mcc_quota_core_write(NULL, 0, 0, 0));
    CHECK(!memcmp(&core, &before, sizeof(core)));
    core.reads = core.writes = core.broadcast_writes = UINT64_MAX;
    CHECK(apple_modern_mcc_quota_core_read(&core, 0, 0, &value));
    CHECK(apple_modern_mcc_quota_core_write(&core, 4, 0, 1));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX &&
          core.broadcast_writes == UINT64_MAX);
    apple_modern_mcc_quota_core_reset(&core);
    CHECK(!core.reads && !core.writes && !core.broadcast_writes);
    for (unsigned plane = 0; plane < 4; plane++) {
        for (unsigned group = 0; group < 32; group++) {
            CHECK(core.values[plane][group] == core.reset_value);
        }
    }

    CHECK(argc == 2);
    FILE *file = fopen(argv[1], "rb"); CHECK(file);
    CHECK(!fseek(file, 0, SEEK_END)); long length = ftell(file);
    CHECK(length > 0 && length < 1 << 20); rewind(file);
    uint8_t *tree = malloc(length); CHECK(tree);
    CHECK(fread(tree, 1, length, file) == (size_t)length); fclose(file);
    AppleModernBlob blob = {tree, length}, property;
    AppleModernMCCQuotaPlan plan;
    Error *error = NULL;
    const uint64_t dram = UINT64_C(0x10000000000), size = UINT64_C(8) << 30;
    CHECK(apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    for (unsigned i = 0; i < 5; i++) {
        CHECK(plan.addresses[i] == UINT64_C(0x22000a000) + (uint64_t)i * 0x40000);
    }
    for (unsigned i = 0; i < 5; i++) {
        uint64_t address = plan.addresses[i];
        AppleModernAddressRange collision = {address + 124, 4};
        CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size,
              &collision, 1, &plan, &error));
        CHECK(error && !plan.addresses[0]); error_free(error); error = NULL;
        CHECK(!apple_modern_mcc_quota_plan_build(blob, address, 128,
              NULL, 0, &plan, &error));
        CHECK(error && !plan.addresses[0]); error_free(error); error = NULL;
        AppleModernAddressRange adjacent[] = {{address - 4, 4}, {address + 128, 4}};
        CHECK(apple_modern_mcc_quota_plan_build(blob, dram, size,
              adjacent, 2, &plan, &error));
    }
    const char *names[] = {"compatible", "amcc-reg-idx", "dcs-count-per-amcc", "amcc-count", "reg"};
    for (unsigned i = 0; i < 5; i++) {
        CHECK(apple_modern_adt_property(blob, "/arm-io/mcc", names[i], &property, &error));
        size_t offset = i == 4 ? 2 * 16 : 0;
        uint8_t *byte = (uint8_t *)property.data + offset; *byte ^= 1;
        CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 0, &plan, &error));
        CHECK(error && !plan.addresses[0]); error_free(error); error = NULL; *byte ^= 1;
    }
    CHECK(apple_modern_adt_property(blob, "/arm-io", "ranges", &property, &error));
    CHECK(property.size >= 48);
    uint8_t saved[24]; memcpy(saved, property.data + 24, 24);
    memcpy((uint8_t *)property.data + 24, property.data, 24);
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(error && !plan.addresses[0]); error_free(error); error = NULL;
    memcpy((uint8_t *)property.data + 24, saved, 24);
    uint8_t *parent = (uint8_t *)property.data + 8; *parent ^= 1;
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(error && !plan.addresses[0]); error_free(error); error = NULL; *parent ^= 1;
    memcpy(saved, property.data, 24);
    memset((uint8_t *)property.data + 16, 0xff, 8);
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(error && !plan.addresses[0]); error_free(error); error = NULL;
    memcpy((uint8_t *)property.data, saved, 24);
    AppleModernAddressRange wrap = {UINT64_MAX, 4}, empty = {0, 0};
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, &wrap, 1, &plan, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, &empty, 1, &plan, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 1, &plan, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_quota_plan_build(blob, UINT64_MAX, size, NULL, 0, &plan, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, 0, NULL, 0, &plan, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 0, NULL, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 0,
                   (AppleModernMCCQuotaPlan *)(void *)tree, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(apple_modern_mcc_quota_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    free(tree);
    printf("{\"passed\":true,\"checks\":%u,\"firmware_executed\":false}\n", checks);
    return 0;
}
