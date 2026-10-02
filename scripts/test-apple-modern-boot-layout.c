/* Same production parser/layout source, with a small standalone Error adapter.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *    hw/arm/apple-silicon/modern-boot-layout.c \
 *    scripts/test-apple-modern-boot-layout.c -o /tmp/test-modern-layout
 */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-boot-layout.h"

#define PAGE 0x4000U
static unsigned checks;

static void put32(uint8_t *p, uint32_t x)
{
    for (unsigned i = 0; i < 4; i++) { p[i] = x >> (8 * i); }
}
static void put64(uint8_t *p, uint64_t x)
{
    put32(p, x); put32(p + 4, x >> 32);
}

static AppleModernBlob image(const char *const *names, unsigned count,
                             uint64_t va, bool fileset)
{
    uint8_t *d = calloc(count, PAGE);
    size_t cursor = 32;
    assert(d);
    put32(d, 0xfeedfacf); put32(d + 4, 0x0100000c);
    put32(d + 8, 0xc0000002); put32(d + 12, fileset ? 12 : 2);
    put32(d + 16, count + 2 + fileset);
    for (unsigned i = 0; i < count; i++) {
        uint8_t *s = d + cursor;
        put32(s, 0x19); put32(s + 4, 72); strcpy((char *)s + 8, names[i]);
        put64(s + 24, va + i * PAGE); put64(s + 32, PAGE);
        put64(s + 40, i * PAGE); put64(s + 48, PAGE);
        put32(s + 56, 7); put32(s + 60, strstr(names[i], "EXEC") ? 5 : 1);
        cursor += 72;
    }
    put32(d + cursor, 5); put32(d + cursor + 4, 288);
    put32(d + cursor + 8, 6); put32(d + cursor + 12, 68);
    for (unsigned i = 0; i < count; i++) {
        if (strstr(names[i], "EXEC")) {
            put64(d + cursor + 272, va + i * PAGE + 0x100); break;
        }
    }
    cursor += 288;
    put32(d + cursor, 0x1b); put32(d + cursor + 4, 24); /* UUID */
    cursor += 24;
    if (fileset) {
        put32(d + cursor, 0x80000035); put32(d + cursor + 4, 56);
        put64(d + cursor + 8, va + PAGE); put64(d + cursor + 16, PAGE);
        put32(d + cursor + 24, 32); strcpy((char *)d + cursor + 32, "com.apple.kernel");
        cursor += 56;
        put32(d + PAGE, 0xfeedfacf); put32(d + PAGE + 4, 0x0100000c);
        put32(d + PAGE + 8, 0xc0000002); put32(d + PAGE + 12, 2);
        put32(d + PAGE + 16, 1); put32(d + PAGE + 20, 24);
        put32(d + PAGE + 32, 0x1b); put32(d + PAGE + 36, 24);
    }
    put32(d + 20, cursor - 32);
    return (AppleModernBlob){ d, count * PAGE };
}

static void prop(uint8_t *d, size_t *cursor, const char *name, const char *value)
{
    size_t len = strlen(value) + 1;
    strcpy((char *)d + *cursor, name);
    put32(d + *cursor + 32, len);
    memcpy(d + *cursor + 36, value, len);
    *cursor += 36 + ((len + 3) & ~3U);
}

static AppleModernBootInput fixture(void)
{
    static const char *const b[] = {"__TEXT_EXEC", "__TEXT_BOOT_EXEC", "__TEXT", "__PRELINK_TEXT", "__DATA_CONST", "__DATA_SPTM", "__PRELINK_INFO", "__DATA", "__LINKEDIT"};
    static const char *const s[] = {"__TEXT", "__DATA_CONST", "__LATE_CONST", "__TEXT_EXEC", "__LAST", "__DATA", "__BOOTDATA", "__LINKEDIT"};
    static const char *const t[] = {"__TEXT", "__DATA_CONST", "__TEXT_EXEC", "__TEXT_BOOT_EXEC", "__DATA", "__LINKEDIT"};
    uint8_t *dt = calloc(1, 1024), *tc = calloc(1, 46);
    size_t p = 8;
    AppleModernBootInput in = { .dram_base = UINT64_C(1) << 40,
                               .dram_size = UINT64_C(8) << 30 };
    assert(dt && tc);
    in.bootkc = image(b, 9, UINT64_C(0xfffffff007004000), true);
    in.sptm = image(s, 8, UINT64_C(0xfffffff027004000), false);
    in.txm = image(t, 6, UINT64_C(0xfffffff017004000), false);
    put32(dt, 1); put32(dt + 4, 2); prop(dt, &p, "name", "/");
    put32(dt + p, 2); p += 8; prop(dt, &p, "name", "arm-io");
    prop(dt, &p, "compatible", "arm-io,t8140");
    put32(dt + p, 1); put32(dt + p + 4, 1); p += 8; prop(dt, &p, "name", "cpus");
    put32(dt + p, 1); p += 8; prop(dt, &p, "name", "cpu0");
    in.dtree = (AppleModernBlob){dt, p};
    put32(tc, 1); put32(tc + 20, 1);
    in.trustcache = (AppleModernBlob){tc, 46};
    return in;
}

static void rejected(const char *name, const AppleModernBootInput *input)
{
    AppleModernBootLayout out, zero = {0};
    Error *err = NULL;
    memset(&out, 0x5a, sizeof(out));
    assert(!apple_modern_boot_layout_build(input, &out, &err));
    assert(err && err->message[0]);
    assert(!memcmp(&out, &zero, sizeof(out)));
    printf("REJECT %s: %s\n", name, err->message);
    error_free(err); checks++;
}

static void mutate32(const char *name, AppleModernBootInput *in,
                     AppleModernBlob blob, size_t offset, uint32_t value)
{
    uint8_t old[4];
    memcpy(old, blob.data + offset, 4);
    put32((uint8_t *)blob.data + offset, value);
    rejected(name, in);
    memcpy((uint8_t *)blob.data + offset, old, 4);
}

static void swapped_sptm_addresses(AppleModernBootInput *in)
{
    uint8_t *first = (uint8_t *)in->sptm.data + 32 + 72 + 24;
    uint8_t *second = first + 72;
    uint8_t old_first[8], old_second[8];
    memcpy(old_first, first, 8); memcpy(old_second, second, 8);
    memcpy(first, old_second, 8); memcpy(second, old_first, 8);
    rejected("permuted SPTM segment addresses", in);
    memcpy(first, old_first, 8); memcpy(second, old_second, 8);
}

static AppleModernBlob file(const char *dir, const char *name)
{
    char path[4096];
    FILE *f;
    long size;
    uint8_t *data;
    assert(snprintf(path, sizeof(path), "%s/%s", dir, name) < (int)sizeof(path));
    f = fopen(path, "rb"); assert(f);
    assert(!fseek(f, 0, SEEK_END)); size = ftell(f); assert(size > 0 && size < 512L * 1024 * 1024);
    rewind(f); data = malloc(size); assert(data);
    assert(fread(data, 1, size, f) == (size_t)size); assert(!fclose(f));
    return (AppleModernBlob){data, size};
}

static void dump_layout(const AppleModernBootLayout *out)
{
    printf("LAYOUT platform=%s nodes=%u filesets=%u regions=%zu copies=%zu\n",
           out->platform, out->dtree_node_count, out->fileset_entry_count,
           out->region_count, out->copy_count);
    printf("ENTRY physical=0x%016" PRIx64 " x0_bootargs=0x%016" PRIx64
           " dtree=0x%016" PRIx64 " top=0x%016" PRIx64 "\n",
           out->sptm_entry_physical, out->bootargs_physical,
           out->dtree_physical, out->top_of_kernel_data);
    for (size_t i = 0; i < out->region_count; i++) {
        const AppleModernBootRegion *r = &out->regions[i];
        printf("REGION %-16s 0x%016" PRIx64 " 0x%016" PRIx64 "\n",
               r->name, r->physical_address, r->size);
    }
    for (size_t i = 0; i < out->copy_count; i++) {
        const AppleModernBootCopy *c = &out->copies[i];
        printf("COPY %u %-17s src=0x%016" PRIx64 " file=0x%016" PRIx64
               " dst=0x%016" PRIx64 " memory=0x%016" PRIx64 "\n",
               c->image, c->segment, c->source_offset, c->file_size,
               c->physical_address, c->memory_size);
    }
}

int main(int argc, char **argv)
{
    AppleModernBootInput in = fixture(), changed;
    AppleModernBootLayout out, repeated;
    Error *err = NULL;
    if (!apple_modern_boot_layout_build(&in, &out, &err)) {
        fprintf(stderr, "%s\n", err ? err->message : "failure without error");
        return 1;
    }
    assert(!err && out.region_count == 19 && out.copy_count == 24);
    assert(out.sptm_entry_physical && out.bootargs_physical);
    checks++;
    changed = in; changed.bootkc.size = 31; rejected("truncated Mach-O", &changed);
    mutate32("wrong ABI", &in, in.bootkc, 8, 0);
    mutate32("wrong file type", &in, in.bootkc, 12, 2);
    mutate32("command table out of bounds", &in, in.bootkc, 20, 0xffffffff);
    mutate32("command size too small", &in, in.bootkc, 36, 4);
    mutate32("segment file extent out of bounds", &in, in.bootkc, 32 + 48, 0xffffffff);
    mutate32("entry outside executable bytes", &in, in.bootkc, 32 + 9 * 72 + 272, 0);
    mutate32("fileset child outside image", &in, in.bootkc, 32 + 9 * 72 + 288 + 24 + 16, 0xffffffff);
    mutate32("fileset child command outside image", &in, in.bootkc, PAGE + 20, 0xffffffff);
    mutate32("fileset child wrong ABI", &in, in.bootkc, PAGE + 8, 0);
    put32((uint8_t *)in.bootkc.data + PAGE + 20, 0);
    mutate32("fileset child empty command table", &in, in.bootkc, PAGE + 16, 0);
    put32((uint8_t *)in.bootkc.data + PAGE + 20, 24);
    put32((uint8_t *)in.bootkc.data + PAGE + 32 + 16, 1);
    mutate32("encrypted fileset child", &in, in.bootkc, PAGE + 32, 0x2c);
    put32((uint8_t *)in.bootkc.data + PAGE + 32 + 16, 0);
    put32((uint8_t *)in.bootkc.data + 32 + 9 * 72 + 288 + 16, 1);
    mutate32("encrypted image", &in, in.bootkc, 32 + 9 * 72 + 288, 0x2c);
    put32((uint8_t *)in.bootkc.data + 32 + 9 * 72 + 288 + 16, 0);
    swapped_sptm_addresses(&in);
    changed = in; changed.dtree.size--; rejected("truncated ADT", &changed);
    mutate32("ADT property out of bounds", &in, in.dtree, 8 + 32, 0x7fffffff);
    mutate32("ADT excessive property count", &in, in.dtree, 0, 0xffffffff);
    changed = in; changed.trustcache.size--; rejected("trustcache bounds mismatch", &changed);
    mutate32("unsupported trustcache version", &in, in.trustcache, 0, 2);
    changed = in; changed.trustcache.data = NULL; rejected("missing trustcache", &changed);
    changed = in; changed.dram_size = 16 * 1024 * 1024; rejected("insufficient DRAM", &changed);
    changed = in; changed.dram_size = (UINT64_C(1) << 36) + PAGE;
    rejected("DRAM exceeds virtual index window", &changed);
    changed = in; changed.dram_size = UINT64_MAX - in.dram_base + 1; rejected("DRAM overflow", &changed);
    assert(apple_modern_boot_layout_build(&in, &repeated, &err));
    assert(!memcmp(&out, &repeated, sizeof(out))); checks++;
    if (argc == 2) {
        AppleModernBootInput actual = { .dram_base = UINT64_C(1) << 40,
                                       .dram_size = UINT64_C(8) << 30 };
        actual.bootkc = file(argv[1], "bootkc"); actual.sptm = file(argv[1], "sptm");
        actual.txm = file(argv[1], "txm"); actual.dtree = file(argv[1], "dtree");
        actual.trustcache = file(argv[1], "restore-trustcache");
        if (!apple_modern_boot_layout_build(&actual, &out, &err)) {
            fprintf(stderr, "%s\n", err ? err->message : "failure without error");
            return 1;
        }
        dump_layout(&out); checks++;
        free((void *)actual.bootkc.data); free((void *)actual.sptm.data);
        free((void *)actual.txm.data); free((void *)actual.dtree.data); free((void *)actual.trustcache.data);
    }
    free((void *)in.bootkc.data); free((void *)in.sptm.data); free((void *)in.txm.data);
    free((void *)in.dtree.data); free((void *)in.trustcache.data);
    printf("PASS %u semantic checks; preparation only, no guest execution\n", checks);
    return 0;
}
