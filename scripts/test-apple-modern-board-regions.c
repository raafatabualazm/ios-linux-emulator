/* Production-source register-RAM planning regression; no guest execution.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-board-regions.h"

static unsigned checks;

static void put32(uint8_t *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++) {
        p[i] = v >> (8 * i);
    }
}

static void put64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) {
        p[i] = v >> (8 * i);
    }
}

typedef struct Fixture {
    uint8_t bytes[4096];
    size_t size, cpu_header, cpu_value, cpm_value;
} Fixture;

static void property(Fixture *f, const char *name, const void *data, size_t size)
{
    uint8_t *p = f->bytes + f->size;
    assert(strlen(name) < 32 && f->size + 36 + size + 3 < sizeof(f->bytes));
    memcpy(p, name, strlen(name) + 1);
    put32(p + 32, size);
    memcpy(p + 36, data, size);
    f->size += 36 + ((size + 3) & ~(size_t)3);
}

static void node(Fixture *f, uint32_t props, uint32_t children)
{
    put32(f->bytes + f->size, props);
    put32(f->bytes + f->size + 4, children);
    f->size += 8;
}

static Fixture fixture(size_t cpu_size, bool duplicate)
{
    Fixture f = {0};
    uint8_t tuple[32] = {0};
    node(&f, 2, 1);
    property(&f, "name", "device-tree", sizeof("device-tree"));
    property(&f, "keep-root", "unchanged", sizeof("unchanged"));
    node(&f, 1, 1);
    property(&f, "name", "cpus", sizeof("cpus"));
    node(&f, duplicate ? 5 : 4, 0);
    property(&f, "name", "cpu0", sizeof("cpu0"));
    property(&f, "keep-policy", "original", sizeof("original"));
    put64(tuple, UINT64_C(0x210050000));
    put64(tuple + 8, UINT64_C(0x9010));
    f.cpu_header = f.size;
    f.cpu_value = f.size + 36;
    property(&f, "cpu-impl-reg", tuple, cpu_size);
    put64(tuple, UINT64_C(0x210e40000));
    put64(tuple + 8, UINT64_C(0xc010));
    f.cpm_value = f.size + 36;
    property(&f, "cpm-impl-reg", tuple, 16);
    if (duplicate) {
        property(&f, "cpu-impl-reg", tuple, 16);
    }
    return f;
}

static AppleModernBlob blob(Fixture *f)
{
    return (AppleModernBlob){f->bytes, f->size};
}

static void rejected(const char *name, AppleModernBlob tree,
                     uint64_t dram_base, uint64_t dram_size,
                     const AppleModernAddressRange *excluded, size_t count)
{
    AppleModernBoardRegions output, zero = {0};
    Error *error = NULL;
    memset(&output, 0x5a, sizeof(output));
    assert(!apple_modern_board_regions_build(tree, dram_base, dram_size,
                                             excluded, count, &output, &error));
    assert(error && !memcmp(&output, &zero, sizeof(output)));
    printf("REJECT %s: %s\n", name, error->message);
    error_free(error);
    checks++;
}

#define REJECT(n) rejected(n, blob(&f), UINT64_C(1) << 40, \
                           UINT64_C(8) << 30, NULL, 0)

static void accepted(AppleModernBlob tree, const AppleModernAddressRange *excluded,
                     size_t count, bool actual)
{
    AppleModernBoardRegions output;
    Error *error = NULL;
    uint8_t *before = malloc(tree.size);
    assert(before);
    memcpy(before, tree.data, tree.size);
    assert(apple_modern_board_regions_build(tree, UINT64_C(1) << 40,
               UINT64_C(8) << 30, excluded, count, &output, &error));
    assert(!error && output.count == 2 && output.total_size == 0x15020);
    assert(!strcmp(output.windows[0].name, "apple-modern.cpu-impl-reg"));
    assert(!strcmp(output.windows[1].name, "apple-modern.cpm-impl-reg"));
    assert(output.windows[0].physical_address == UINT64_C(0x210050000));
    assert(output.windows[0].size == 0x9010);
    assert(output.windows[1].physical_address == UINT64_C(0x210e40000));
    assert(output.windows[1].size == 0xc010);
    assert(!memcmp(before, tree.data, tree.size));
    free(before);
    if (actual) {
        for (size_t i = 0; i < output.count; i++) {
            printf("WINDOW %s 0x%llx 0x%llx\n", output.windows[i].name,
                   (unsigned long long)output.windows[i].physical_address,
                   (unsigned long long)output.windows[i].size);
        }
    }
    checks++;
}

static AppleModernBlob read_file(const char *path)
{
    FILE *source = fopen(path, "rb");
    long size;
    uint8_t *data;
    assert(source && !fseek(source, 0, SEEK_END));
    size = ftell(source);
    assert(size > 0 && size < 16 * 1024 * 1024 && !fseek(source, 0, SEEK_SET));
    data = malloc(size);
    assert(data && fread(data, 1, size, source) == (size_t)size);
    assert(!fclose(source));
    return (AppleModernBlob){data, size};
}

int main(int argc, char **argv)
{
    Fixture f = fixture(16, false);
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1];
    AppleModernBoardRegions output;
    Error *error = NULL;

    accepted(blob(&f), NULL, 0, false);
    exclusions[0] = (AppleModernAddressRange){0x210049000, 0x7000};
    exclusions[1] = (AppleModernAddressRange){0x210059010, 0x1000};
    accepted(blob(&f), exclusions, 2, false); /* exact adjacency is allowed */
    exclusions[0].size++;
    rejected("left overlap by one byte", blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, exclusions, 2);
    exclusions[0] = (AppleModernAddressRange){0x210050000, 0x1000};
    rejected("UART/other mapped register overlap", blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, exclusions, 1);
    rejected("DRAM overlap", blob(&f), 0x210050000, 0x100000, NULL, 0);
    rejected("zero DRAM", blob(&f), UINT64_C(1) << 40, 0, NULL, 0);
    rejected("wrapping DRAM", blob(&f), UINT64_MAX - 1, 2, NULL, 0);
    rejected("missing exclusions", blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, NULL, 1);
    rejected("exclusion count cap", blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, exclusions,
             APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1);
    exclusions[0] = (AppleModernAddressRange){0x100, 0};
    rejected("zero exclusion", blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, exclusions, 1);
    exclusions[0] = (AppleModernAddressRange){UINT64_MAX - 1, 2};
    rejected("wrapping exclusion", blob(&f), UINT64_C(1) << 40,
             UINT64_C(8) << 30, exclusions, 1);
    for (size_t i = 0; i < APPLE_MODERN_MAX_BOARD_EXCLUSIONS; i++) {
        exclusions[i] = (AppleModernAddressRange){0x1000 + i * 0x1000, 0x1000};
    }
    accepted(blob(&f), exclusions, APPLE_MODERN_MAX_BOARD_EXCLUSIONS, false);
    f = fixture(0, false); REJECT("empty tuple property");
    f = fixture(15, false); REJECT("short tuple property");
    f = fixture(32, false); REJECT("additional tuples unsupported");
    f = fixture(16, true); REJECT("ambiguous duplicate property");
    f = fixture(16, false);
    memcpy(f.bytes + f.cpu_header, "cpu-impl-xxx", sizeof("cpu-impl-xxx"));
    REJECT("missing property");
    f = fixture(16, false); f.size--; REJECT("truncated tree");
    f = fixture(16, false); put64(f.bytes + f.cpu_value + 8, 0);
    REJECT("zero window");
    f = fixture(16, false); put64(f.bytes + f.cpu_value, 0);
    REJECT("zero base placeholder");
    f = fixture(16, false); put64(f.bytes + f.cpu_value, UINT64_MAX - 1);
    REJECT("wrapping window");
    f = fixture(16, false);
    put64(f.bytes + f.cpu_value + 8, APPLE_MODERN_MAX_REGISTER_WINDOW + 1);
    REJECT("window allocation cap");
    f = fixture(16, false); put64(f.bytes + f.cpm_value, 0x210050010);
    REJECT("CPU windows overlap");
    f = fixture(16, false);
    put64(f.bytes + f.cpu_value + 8, APPLE_MODERN_MAX_REGISTER_WINDOW);
    put64(f.bytes + f.cpm_value + 8, APPLE_MODERN_MAX_REGISTER_WINDOW);
    assert(apple_modern_board_regions_build(blob(&f), UINT64_C(1) << 40,
               UINT64_C(8) << 30, NULL, 0, &output, &error));
    assert(!error && output.count == 2 &&
           output.total_size == APPLE_MODERN_MAX_REGISTER_TOTAL);
    checks++;
    f = fixture(16, false);
    {
        Fixture saved = f;
        assert(!apple_modern_board_regions_build(blob(&f), UINT64_C(1) << 40,
                 UINT64_C(8) << 30, NULL, 0,
                 (AppleModernBoardRegions *)f.bytes, &error));
        assert(error && !memcmp(&f, &saved, sizeof(f)));
        error_free(error); error = NULL; checks++;
    }
    memset(&output, 0x5a, sizeof(output));
    {
        AppleModernBoardRegions saved = output;
        assert(!apple_modern_board_regions_build(blob(&f), UINT64_C(1) << 40,
                 UINT64_C(8) << 30, (AppleModernAddressRange *)&output, 1,
                 &output, &error));
        assert(error && !memcmp(&output, &saved, sizeof(output)));
        error_free(error); error = NULL; checks++;
    }
    assert(!apple_modern_board_regions_build(blob(&f), UINT64_C(1) << 40,
               UINT64_C(8) << 30, NULL, 0, NULL, &error));
    assert(error); error_free(error); checks++;
    if (argc == 2) {
        AppleModernBlob actual = read_file(argv[1]);
        accepted(actual, NULL, 0, true);
        free((void *)actual.data);
    }
    printf("PASS %u\n", checks);
    return 0;
}
