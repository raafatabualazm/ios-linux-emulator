/* Owned immutable-input and strict matched-layout checks.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-pmgr-fuse.h"
static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

int main(int argc, char **argv)
{
    uint8_t image[APPLE_MODERN_PMGR_FUSE_SIZE];
    AppleModernPMGRFuseCore core = {0};
    Error *error = NULL;
    uint32_t value = 0xfeed;
    CHECK(argc == 2);
    for (size_t i = 0; i < sizeof(image); i++) {
        image[i] = (i * 17) ^ (i >> 7) ^ 0xa5;
    }
    CHECK(!apple_modern_pmgr_fuse_core_read(&core, 0, &value) && value == 0xfeed);
    CHECK(!apple_modern_pmgr_fuse_core_load(&core,
                                          (AppleModernBlob){image, 0}, &error));
    CHECK(error != NULL && !core.loaded); error_free(error); error = NULL;
    CHECK(apple_modern_pmgr_fuse_core_load(&core,
                              (AppleModernBlob){image, sizeof(image)}, &error));
    CHECK(core.loaded && !error && !memcmp(core.image, image, sizeof(image)));
    /* The core owns its copy, independent of subsequent source-buffer changes. */
    image[0] ^= 0xff;
    CHECK(core.image[0] == 0xa5); image[0] ^= 0xff;
    for (size_t i = 0; i < sizeof(image); i += 4) {
        uint32_t expected;
        memcpy(&expected, image + i, 4); /* owned little-endian Linux oracle */
        CHECK(apple_modern_pmgr_fuse_core_read(&core, i, &value));
        CHECK(value == expected);
    }
    CHECK(core.reads == sizeof(image) / 4);
    value = 0xfeed;
    CHECK(!apple_modern_pmgr_fuse_core_read(&core, 1, &value) && value == 0xfeed);
    CHECK(!apple_modern_pmgr_fuse_core_read(&core, sizeof(image), &value));
    CHECK(!apple_modern_pmgr_fuse_core_read(&core, UINT64_MAX - 3, &value));
    CHECK(!apple_modern_pmgr_fuse_core_read(&core, 0, (uint32_t *)core.image));
    CHECK(!apple_modern_pmgr_fuse_core_load(&core,
                                (AppleModernBlob){core.image, sizeof(image)}, &error));
    CHECK(error && !memcmp(core.image, image, sizeof(image)));
    error_free(error); error = NULL;
    core.reads = UINT64_MAX;
    CHECK(apple_modern_pmgr_fuse_core_read(&core, 0, &value));
    CHECK(core.reads == UINT64_MAX);
    core.rejected_writes = 37;
    apple_modern_pmgr_fuse_core_reset(&core);
    CHECK(core.loaded && !core.reads && !core.rejected_writes);
    CHECK(!memcmp(core.image, image, sizeof(image)));

    FILE *file = fopen(argv[1], "rb"); CHECK(file != NULL);
    CHECK(!fseek(file, 0, SEEK_END)); long length = ftell(file);
    CHECK(length > 0 && length < 1 << 20); rewind(file);
    uint8_t *tree = malloc(length); CHECK(tree != NULL);
    CHECK(fread(tree, 1, length, file) == (size_t)length); fclose(file);
    AppleModernBlob blob = {tree, length}, reg, ranges;
    AppleModernPMGRFusePlan plan = {0};
    const uint64_t dram = UINT64_C(0x10000000000), dram_size = UINT64_C(8) << 30;
    CHECK(apple_modern_pmgr_fuse_plan_build(blob, dram, dram_size, NULL, 0,
                                          &plan, &error));
    CHECK(plan.base == APPLE_MODERN_PMGR_FUSE_BASE && plan.size == sizeof(image));
    CHECK(!memcmp(core.image, image, sizeof(image)));
    AppleModernAddressRange hole = {UINT64_C(0x3082dc000), 0x4000};
    CHECK(apple_modern_pmgr_fuse_plan_build(blob, dram, dram_size, &hole, 1,
                                          &plan, &error));
    AppleModernAddressRange overlap = {APPLE_MODERN_PMGR_FUSE_BASE + 0x100, 4};
    CHECK(!apple_modern_pmgr_fuse_plan_build(blob, dram, dram_size, &overlap, 1,
                                           &plan, &error));
    CHECK(error && !plan.base && !plan.size); error_free(error); error = NULL;
    CHECK(apple_modern_adt_property(blob, "/arm-io/pmgr", "reg", &reg, &error));
    uint8_t *bank = (uint8_t *)reg.data + 30 * 16;
    bank[8] ^= 1;
    CHECK(!apple_modern_pmgr_fuse_plan_build(blob, dram, dram_size, NULL, 0,
                                           &plan, &error));
    CHECK(error && !plan.base); error_free(error); error = NULL; bank[8] ^= 1;
    bank[0] ^= 1;
    CHECK(!apple_modern_pmgr_fuse_plan_build(blob, dram, dram_size, NULL, 0,
                                           &plan, &error));
    CHECK(error && !plan.base); error_free(error); error = NULL; bank[0] ^= 1;
    CHECK(apple_modern_adt_property(blob, "/arm-io", "ranges", &ranges, &error));
    uint8_t *parent = (uint8_t *)ranges.data + 8; parent[0] ^= 1;
    CHECK(!apple_modern_pmgr_fuse_plan_build(blob, dram, dram_size, NULL, 0,
                                           &plan, &error));
    CHECK(error && !plan.base); error_free(error); error = NULL; parent[0] ^= 1;
    CHECK(!apple_modern_pmgr_fuse_plan_build(blob, dram, dram_size, NULL, 0,
                 (AppleModernPMGRFusePlan *)(void *)tree, &error));
    CHECK(error); error_free(error); error = NULL;
    CHECK(apple_modern_pmgr_fuse_plan_build(blob, dram, dram_size, NULL, 0,
                                          &plan, &error));
    free(tree);
    printf("{\"passed\":true,\"checks\":%u,\"firmware_executed\":false}\n", checks);
    return 0;
}
