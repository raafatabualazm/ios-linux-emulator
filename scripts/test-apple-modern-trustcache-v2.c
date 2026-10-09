/* Trust-cache module version acceptance: version 1 always, version 2 only
 * when the caller opts in. Production-source test, preparation only, no guest
 * launch and no entry of any trust cache is parsed, compared or written.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *   -fsanitize=address,undefined -fno-omit-frame-pointer \
 *   hw/arm/apple-silicon/modern-boot-layout.c \
 *   scripts/test-apple-modern-trustcache-v2.c -o /tmp/test-tcv2 \
 *   && /tmp/test-tcv2 [components-dir]
 *
 * With a components directory the five real decoded components are laid out
 * twice: once with the directory's `restore-trustcache` (Apple's version-1
 * restore module) and once with its `static-trustcache` (Apple's version-2
 * static module) if that file exists, printing the resulting TrustCache
 * region so the guest-side address can be read off loader state.
 */
#define main layout_regression_main
#include "test-apple-modern-boot-layout.c"
#undef main
#include <unistd.h>

static unsigned tc_checks;

static uint32_t tc_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

/* A bare module: 24-byte header then count zero-filled entries. The declared
 * byte count is independent of the header so truncation, overlong tails and
 * inconsistent counts can all be presented to the validator.
 */
static AppleModernBlob module(uint32_t version, uint32_t count, size_t bytes)
{
    uint8_t *d;
    assert(bytes);
    d = calloc(1, bytes);
    assert(d);
    if (bytes >= 4) {
        put32(d, version);
    }
    if (bytes >= 24) {
        put32(d + 20, count);
    }
    return (AppleModernBlob){d, bytes};
}

static void refused(const char *name, const AppleModernBootInput *in,
                    const char *expected)
{
    AppleModernBootLayout out, zero = {0};
    Error *err = NULL;
    memset(&out, 0x5a, sizeof(out));
    if (apple_modern_boot_layout_build(in, &out, &err)) {
        fprintf(stderr, "FAIL %s was accepted\n", name);
        exit(1);
    }
    if (!err || !strstr(err->message, expected)) {
        fprintf(stderr, "FAIL %s: message \"%s\" lacks \"%s\"\n", name,
                err ? err->message : "(none)", expected);
        exit(1);
    }
    if (memcmp(&out, &zero, sizeof(out))) {
        fprintf(stderr, "FAIL %s: output not cleared on failure\n", name);
        exit(1);
    }
    printf("REFUSE %-42s %s\n", name, err->message);
    error_free(err);
    tc_checks++;
}

static void accepted(const char *name, const AppleModernBootInput *in,
                     AppleModernBootLayout *out)
{
    Error *err = NULL;
    memset(out, 0x5a, sizeof(*out));
    if (!apple_modern_boot_layout_build(in, out, &err)) {
        fprintf(stderr, "FAIL %s was refused: %s\n", name,
                err ? err->message : "(no error)");
        exit(1);
    }
    assert(!err);
    printf("ACCEPT %s\n", name);
    tc_checks++;
}

static const AppleModernBootCopy *trustcache_copy(const AppleModernBootLayout *l)
{
    for (size_t i = 0; i < l->copy_count; i++) {
        if (l->copies[i].image == APPLE_MODERN_TRUSTCACHE) {
            return &l->copies[i];
        }
    }
    fprintf(stderr, "FAIL no trustcache copy in the layout\n");
    exit(1);
}

static const AppleModernBootRegion *trustcache_region(const AppleModernBootLayout *l)
{
    for (size_t i = 0; i < l->region_count; i++) {
        if (!strcmp(l->regions[i].name, "TrustCache")) {
            return &l->regions[i];
        }
    }
    fprintf(stderr, "FAIL no TrustCache region in the layout\n");
    exit(1);
}

/* The module bytes are reserved verbatim behind the 8-byte catalog offsets
 * header, so a v1 and a v2 module whose reservations round to the same page
 * count must produce byte-identical layouts apart from the copy's own extents.
 */
static void same_layout_except_extents(const char *name,
                                       const AppleModernBootLayout *v1,
                                       const AppleModernBootLayout *v2,
                                       uint64_t expected_bytes)
{
    AppleModernBootLayout patched = *v2;
    const AppleModernBootCopy *copy = trustcache_copy(v2);
    size_t index = (size_t)(copy - v2->copies);
    if (copy->file_size != expected_bytes ||
        copy->memory_size != expected_bytes) {
        fprintf(stderr, "FAIL %s: copy extents %" PRIu64 "/%" PRIu64
                " not %" PRIu64 "\n", name, copy->file_size,
                copy->memory_size, expected_bytes);
        exit(1);
    }
    patched.copies[index].file_size = v1->copies[index].file_size;
    patched.copies[index].memory_size = v1->copies[index].memory_size;
    if (memcmp(&patched, v1, sizeof(patched))) {
        fprintf(stderr, "FAIL %s: layout differs beyond the copy extents\n",
                name);
        exit(1);
    }
    printf("SAME %s (only the trustcache copy extents differ)\n", name);
    tc_checks++;
}

static void versions(void)
{
    AppleModernBootInput in = fixture(), changed;
    AppleModernBootLayout v1 = {0}, v1_opt = {0}, out = {0};
    const uint8_t *header;

    /* (1) The shipping default: a version-1 module, opt-in off. */
    accepted("v1 module, trustcache_v2 off", &in, &v1);
    header = v1.trustcache_offsets_header;
    assert(trustcache_copy(&v1)->file_size == 46);
    assert(trustcache_region(&v1)->size == APPLE_MODERN_PAGE_SIZE);
    assert(header[0] == 1 && header[4] == 8);
    tc_checks++;

    /* (2) The opt-in must not alter a version-1 layout at all. */
    changed = in;
    changed.trustcache_v2 = true;
    accepted("v1 module, trustcache_v2 on", &changed, &v1_opt);
    if (memcmp(&v1_opt, &v1, sizeof(v1))) {
        fprintf(stderr, "FAIL the opt-in changed a version-1 layout\n");
        exit(1);
    }
    printf("SAME v1 layout is byte-identical with the opt-in on\n");
    tc_checks++;

    /* (3) A well-formed version-2 module is refused by the default board. */
    changed = in;
    changed.trustcache = module(2, 1, 48);
    refused("v2 module, opt-in off", &changed,
            "version-2 trustcache needs trustcache-v2=on");

    /* (4) ... and accepted with the opt-in, reserving its own bytes. */
    changed.trustcache_v2 = true;
    accepted("v2 module, opt-in on", &changed, &out);
    same_layout_except_extents("v2 module vs v1 module", &v1, &out, 48);
    assert(trustcache_region(&out)->size == APPLE_MODERN_PAGE_SIZE);
    assert(!memcmp(out.trustcache_offsets_header, header, 8));
    tc_checks++;

    /* (5) Truncated, overlong and inconsistent version-2 geometry. */
    free((void *)changed.trustcache.data);
    changed.trustcache = module(2, 1, 47);
    refused("v2 truncated by one byte", &changed,
            "version-2 trustcache entry count does not match length");
    free((void *)changed.trustcache.data);
    changed.trustcache = module(2, 1, 49);
    refused("v2 overlong by one byte", &changed,
            "version-2 trustcache entry count does not match length");
    free((void *)changed.trustcache.data);
    changed.trustcache = module(2, 2, 48);
    refused("v2 count larger than the length", &changed,
            "version-2 trustcache entry count does not match length");
    free((void *)changed.trustcache.data);
    changed.trustcache = module(2, 0, 24);
    refused("v2 empty module", &changed,
            "version-2 trustcache entry count does not match length");
    free((void *)changed.trustcache.data);
    /* Version 1's 22-byte entries do not fit a version-2 length, and the
     * reverse, so the entry size is really keyed to the version word. */
    changed.trustcache = module(1, 1, 48);
    refused("v1 header with a v2 length", &changed,
            "missing or malformed version-1 trustcache");
    free((void *)changed.trustcache.data);
    changed.trustcache = module(2, 1, 46);
    refused("v2 header with a v1 length", &changed,
            "version-2 trustcache entry count does not match length");
    free((void *)changed.trustcache.data);

    /* (6) Counts that only fit if the scaling wraps at 32 bits. With 22-byte
     * entries 0x80000001 * 22 + 24 is congruent to 46 modulo 2^32, and with
     * 24-byte entries 0x20000001 * 24 + 24 is congruent to 48, so a 32-bit
     * multiply would accept both of these as exactly sized.
     */
    changed.trustcache = module(2, UINT32_C(0x20000001), 48);
    refused("v2 count wrapping at 32 bits", &changed,
            "version-2 trustcache entry count does not match length");
    free((void *)changed.trustcache.data);
    changed.trustcache = module(1, UINT32_C(0x80000001), 46);
    refused("v1 count wrapping at 32 bits", &changed,
            "missing or malformed version-1 trustcache");
    free((void *)changed.trustcache.data);
    changed.trustcache = module(2, UINT32_MAX, 48);
    refused("v2 count at the 32-bit maximum", &changed,
            "version-2 trustcache entry count does not match length");
    free((void *)changed.trustcache.data);

    /* (7) Unsupported versions, with and without the opt-in. */
    changed.trustcache = module(0, 1, 46);
    refused("version 0, opt-in on", &changed,
            "trustcache module version is neither 1 nor 2");
    changed.trustcache_v2 = false;
    refused("version 0, opt-in off", &changed,
            "missing or malformed version-1 trustcache");
    free((void *)changed.trustcache.data);
    changed.trustcache = module(3, 1, 48);
    refused("version 3, opt-in off", &changed,
            "missing or malformed version-1 trustcache");
    changed.trustcache_v2 = true;
    refused("version 3, opt-in on", &changed,
            "trustcache module version is neither 1 nor 2");
    free((void *)changed.trustcache.data);

    /* (8) Header-sized and sub-header-sized modules, and a missing one. The
     * 23-byte allocation is exact, so any read of the count word would be an
     * out-of-bounds access under the sanitizers.
     */
    changed.trustcache = module(1, 0, 23);
    refused("module shorter than its header", &changed,
            "missing or malformed version-1 trustcache");
    free((void *)changed.trustcache.data);
    changed.trustcache = module(1, 0, 24);
    refused("v1 header with no entries", &changed,
            "missing or malformed version-1 trustcache");
    free((void *)changed.trustcache.data);
    changed = in;
    changed.trustcache_v2 = true;
    changed.trustcache.data = NULL;
    refused("missing module with the opt-in on", &changed,
            "missing or malformed version-1 trustcache");
    /* An exactly sized version-1 module above the loader's 16 MiB module
     * bound: refused on its length, not on its geometry.
     */
    changed = in;
    changed.trustcache = module(1, 800000, 24 + 800000 * 22);
    refused("module above the 16 MiB bound", &changed,
            "missing or malformed version-1 trustcache");
    free((void *)changed.trustcache.data);

    /* (9) Apple's own static-module geometry: 3,808 version-2 entries. The
     * reservation is the page-rounded module plus the 8-byte catalog header.
     */
    changed = in;
    changed.trustcache_v2 = true;
    changed.trustcache = module(2, 3808, 24 + 3808 * 24);
    accepted("v2 module with 3808 entries", &changed, &out);
    assert(trustcache_copy(&out)->file_size == 91416);
    assert(trustcache_region(&out)->size == 6 * APPLE_MODERN_PAGE_SIZE);
    assert(trustcache_copy(&out)->physical_address ==
           trustcache_region(&out)->physical_address + 8);
    tc_checks++;
    free((void *)changed.trustcache.data);

    free((void *)in.bootkc.data);
    free((void *)in.sptm.data);
    free((void *)in.txm.data);
    free((void *)in.dtree.data);
    free((void *)in.trustcache.data);
}

static void actual(const char *directory)
{
    static const char *const names[] = {"restore-trustcache", "static-trustcache"};
    char path[4096];
    for (size_t i = 0; i < 2; i++) {
        AppleModernBootInput in = { .dram_base = UINT64_C(1) << 40,
                                   .dram_size = UINT64_C(8) << 30,
                                   .trustcache_v2 = i == 1 };
        AppleModernBootLayout out;
        assert(snprintf(path, sizeof(path), "%s/%s", directory, names[i]) <
               (int)sizeof(path));
        if (access(path, R_OK)) {
            printf("SKIP %s is absent\n", names[i]);
            continue;
        }
        in.bootkc = file(directory, "bootkc");
        in.sptm = file(directory, "sptm");
        in.txm = file(directory, "txm");
        in.dtree = file(directory, "dtree");
        in.trustcache = file(directory, names[i]);
        accepted(names[i], &in, &out);
        printf("ACTUAL %-18s module=%zu bytes version=%u entries=%u "
               "region=0x%016" PRIx64 "+0x%" PRIx64 " copy=0x%016" PRIx64
               "+0x%" PRIx64 "\n", names[i], in.trustcache.size,
               tc_le32(in.trustcache.data), tc_le32(in.trustcache.data + 20),
               trustcache_region(&out)->physical_address,
               trustcache_region(&out)->size,
               trustcache_copy(&out)->physical_address,
               trustcache_copy(&out)->file_size);
        tc_checks++;
        free((void *)in.bootkc.data);
        free((void *)in.sptm.data);
        free((void *)in.txm.data);
        free((void *)in.dtree.data);
        free((void *)in.trustcache.data);
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (layout_regression_main(1, argv)) {
        return 1;
    }
    versions();
    if (argc == 2) {
        actual(argv[1]);
    }
    printf("PASS %u trustcache-version checks (+%u shared layout checks); "
           "preparation only, no guest execution\n", tc_checks, checks);
    return 0;
}
