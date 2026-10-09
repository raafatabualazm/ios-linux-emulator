/* The opt-in second trust-cache module (the OS cryptex's own module).
 *
 * Production-source test, preparation only: no guest launch, and no entry of
 * any trust cache is parsed, compared, merged or written. What is checked is
 * the catalog geometry the loader publishes -- the iBoot offsets header, the
 * reservation, and the copy extents -- and that the default board, with no
 * second module, is byte-identical to what it produced before the option
 * existed.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *   -fsanitize=address,undefined -fno-omit-frame-pointer \
 *   hw/arm/apple-silicon/modern-boot-layout.c \
 *   scripts/test-apple-modern-cryptex-trustcache.c -o /tmp/test-cryptex-tc \
 *   && /tmp/test-cryptex-tc [components-dir]
 *
 * With a components directory, Apple's own two modules (static-trustcache and
 * os-cryptex-trustcache) are laid out together and the catalog is printed, so
 * the guest-side addresses can be read off loader state.
 */
#define main layout_regression_main
#include "test-apple-modern-boot-layout.c"
#undef main
#include <unistd.h>

static unsigned cx_checks;

static uint64_t cx_page_up(uint64_t v)
{
    return (v + APPLE_MODERN_PAGE_SIZE - 1) & ~(uint64_t)(APPLE_MODERN_PAGE_SIZE - 1);
}

static uint32_t cx_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

/* A bare module: 24-byte header then `count` zero-filled entries. `bytes` is
 * independent of `count` so truncation, overlong tails and inconsistent
 * counts can all be presented to the validator.
 */
static AppleModernBlob cx_module(uint32_t version, uint32_t count, size_t bytes)
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

static void cx_refused(const char *name, const AppleModernBootInput *in,
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
    printf("REFUSE %-44s %s\n", name, err->message);
    error_free(err);
    cx_checks++;
}

static void cx_accepted(const char *name, const AppleModernBootInput *in,
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
    cx_checks++;
}

static const AppleModernBootRegion *cx_region(const AppleModernBootLayout *l)
{
    for (size_t i = 0; i < l->region_count; i++) {
        if (!strcmp(l->regions[i].name, "TrustCache")) {
            return &l->regions[i];
        }
    }
    fprintf(stderr, "FAIL no TrustCache region in the layout\n");
    exit(1);
}

/* The copies for the catalog, in the order the loader recorded them: index 0
 * is the first module, index 1 (when present) the cryptex module.
 */
static size_t cx_copies(const AppleModernBootLayout *l,
                        const AppleModernBootCopy *out[2])
{
    size_t n = 0;
    out[0] = out[1] = NULL;
    for (size_t i = 0; i < l->copy_count; i++) {
        if (l->copies[i].image == APPLE_MODERN_TRUSTCACHE) {
            if (n == 2) {
                fprintf(stderr, "FAIL more than two trustcache copies\n");
                exit(1);
            }
            out[n++] = &l->copies[i];
        }
    }
    if (!n) {
        fprintf(stderr, "FAIL no trustcache copy in the layout\n");
        exit(1);
    }
    return n;
}

static void cx_catalog(const char *name, const AppleModernBootLayout *l,
                       uint32_t modules, uint64_t first, uint64_t second)
{
    const AppleModernBootCopy *copy[2];
    const AppleModernBootRegion *region = cx_region(l);
    const uint8_t *h = l->trustcache_offsets_header;
    uint32_t header = 4 + 4 * modules;
    size_t n = cx_copies(l, copy);

    if (l->trustcache_module_count != modules ||
        l->trustcache_header_size != header || n != modules) {
        fprintf(stderr, "FAIL %s: modules %u/%u header %u/%u copies %zu\n",
                name, l->trustcache_module_count, modules,
                l->trustcache_header_size, header, n);
        exit(1);
    }
    if (cx_le32(h) != modules || cx_le32(h + 4) != header) {
        fprintf(stderr, "FAIL %s: header count %u offset %u\n", name,
                cx_le32(h), cx_le32(h + 4));
        exit(1);
    }
    if (copy[0]->file_size != first || copy[0]->memory_size != first ||
        copy[0]->physical_address != region->physical_address + header) {
        fprintf(stderr, "FAIL %s: first module extents\n", name);
        exit(1);
    }
    if (modules == 1) {
        /* The three bytes past the single-module header stay zero, so the
         * published catalog is byte-identical to the one every revision
         * before this option produced. */
        for (size_t i = 8; i < 12; i++) {
            if (h[i]) {
                fprintf(stderr, "FAIL %s: byte %zu of the header is %u\n",
                        name, i, h[i]);
                exit(1);
            }
        }
        if (region->size != cx_page_up(header + first)) {
            fprintf(stderr, "FAIL %s: reservation 0x%" PRIx64 " is not the "
                    "page-rounded catalog\n", name, region->size);
            exit(1);
        }
    } else {
        uint32_t offset = cx_le32(h + 8);
        if (offset != header + first) {
            fprintf(stderr, "FAIL %s: second offset %u not %" PRIu64 "\n",
                    name, offset, header + first);
            exit(1);
        }
        if (copy[1]->file_size != second || copy[1]->memory_size != second ||
            copy[1]->physical_address != region->physical_address + offset) {
            fprintf(stderr, "FAIL %s: second module extents\n", name);
            exit(1);
        }
        if (strcmp(copy[1]->segment, "catalog-cryptex")) {
            fprintf(stderr, "FAIL %s: second copy is named %s\n", name,
                    copy[1]->segment);
            exit(1);
        }
        if (region->size != cx_page_up(header + first + second)) {
            fprintf(stderr, "FAIL %s: reservation 0x%" PRIx64 " is not the "
                    "page-rounded two-module catalog\n", name, region->size);
            exit(1);
        }
    }
    printf("CATALOG %-36s modules=%u header=%u first=%" PRIu64
           " second=%" PRIu64 " region=0x%" PRIx64 "+0x%" PRIx64 "\n",
           name, modules, header, first, second, region->physical_address,
           region->size);
    cx_checks++;
}

static void cryptex(void)
{
    AppleModernBootInput in = fixture(), changed;
    AppleModernBootLayout base = {0}, zero_size = {0}, two = {0};

    /* (1) The shipping default: one module, no cryptex module at all. */
    in.trustcache_v2 = true;
    cx_accepted("no cryptex module", &in, &base);
    cx_catalog("no cryptex module", &base, 1, 46, 0);

    /* (2) A zero-length cryptex blob is "absent", not "empty": the layout
     * must be the same bytes, not merely equivalent. */
    changed = in;
    changed.cryptex_trustcache = (AppleModernBlob){NULL, 0};
    cx_accepted("NULL/0 cryptex module", &changed, &zero_size);
    if (memcmp(&zero_size, &base, sizeof(base))) {
        fprintf(stderr, "FAIL a NULL/0 cryptex blob changed the layout\n");
        exit(1);
    }
    printf("SAME NULL/0 cryptex blob is byte-identical to absent\n");
    cx_checks++;

    /* (3) A nonzero size with no data is a programming error, not an absence:
     * it must be refused rather than silently reserved. */
    changed = in;
    changed.cryptex_trustcache = (AppleModernBlob){NULL, 3144};
    cx_refused("cryptex size without data", &changed,
               "missing or malformed cryptex trustcache");

    /* (4) Two well-formed version-2 modules. */
    changed = in;
    changed.cryptex_trustcache = cx_module(2, 130, 24 + 130 * 24);
    cx_accepted("v2 first + v2 cryptex", &changed, &two);
    cx_catalog("v2 first + v2 cryptex", &two, 2, 46, 3144);
    /* The first module's own bytes move by exactly the four header bytes the
     * second offset costs, and nothing else about the catalog changes. */
    {
        const AppleModernBootCopy *one[2], *both[2];
        cx_copies(&base, one);
        cx_copies(&two, both);
        if (both[0]->physical_address != one[0]->physical_address + 4 ||
            cx_region(&two)->physical_address !=
            cx_region(&base)->physical_address) {
            fprintf(stderr, "FAIL the second offset moved more than 4 bytes\n");
            exit(1);
        }
        printf("SHIFT the first module moves by exactly the 4 added header "
               "bytes\n");
        cx_checks++;
    }

    /* (5) The version-2 opt-in governs the cryptex module too. */
    changed.trustcache_v2 = false;
    changed.trustcache = cx_module(1, 1, 46);
    cx_refused("v2 cryptex module, opt-in off", &changed,
               "version-2 trustcache needs trustcache-v2=on");
    free((void *)changed.trustcache.data);
    free((void *)changed.cryptex_trustcache.data);

    /* (6) A version-1 cryptex module beside a version-1 first module: the
     * option is not tied to version 2. */
    changed = in;
    changed.trustcache_v2 = false;
    changed.cryptex_trustcache = cx_module(1, 2, 24 + 2 * 22);
    cx_accepted("v1 first + v1 cryptex, opt-in off", &changed, &two);
    cx_catalog("v1 first + v1 cryptex, opt-in off", &two, 2, 46, 68);
    free((void *)changed.cryptex_trustcache.data);

    /* (7) Malformed cryptex geometry is reported as the cryptex module's
     * fault, never as the first module's. */
    changed = in;
    static const struct { uint32_t version, count; size_t bytes;
                          const char *name; } bad[] = {
        {2, 130, 24 + 130 * 24 - 1, "cryptex truncated by one byte"},
        {2, 130, 24 + 130 * 24 + 1, "cryptex overlong by one byte"},
        {2, 131, 24 + 130 * 24, "cryptex count larger than the length"},
        {2, 0, 24, "cryptex empty module"},
        {1, 1, 48, "cryptex v1 header with a v2 length"},
        {2, UINT32_C(0x20000001), 48, "cryptex count wrapping at 32 bits"},
        {2, UINT32_MAX, 48, "cryptex count at the 32-bit maximum"},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        changed.cryptex_trustcache = cx_module(bad[i].version, bad[i].count,
                                               bad[i].bytes);
        cx_refused(bad[i].name, &changed, "cryptex trustcache");
        free((void *)changed.cryptex_trustcache.data);
    }
    changed.cryptex_trustcache = cx_module(0, 1, 46);
    cx_refused("cryptex version 0", &changed,
               "trustcache module version is neither 1 nor 2");
    free((void *)changed.cryptex_trustcache.data);
    changed.cryptex_trustcache = cx_module(1, 0, 23);
    cx_refused("cryptex shorter than its header", &changed,
               "missing or malformed cryptex trustcache");
    free((void *)changed.cryptex_trustcache.data);
    changed.cryptex_trustcache = cx_module(1, 800000, 24 + 800000 * 22);
    cx_refused("cryptex above the 16 MiB bound", &changed,
               "missing or malformed cryptex trustcache");
    free((void *)changed.cryptex_trustcache.data);

    /* (8) A good cryptex module does not excuse a bad first module. */
    changed = in;
    changed.cryptex_trustcache = cx_module(2, 130, 24 + 130 * 24);
    changed.trustcache = cx_module(2, 2, 48);
    cx_refused("good cryptex, first module miscounted", &changed,
               "version-2 trustcache entry count does not match length");
    free((void *)changed.trustcache.data);
    changed.trustcache.data = NULL;
    changed.trustcache.size = 0;
    cx_refused("good cryptex, first module missing", &changed,
               "missing or malformed version-1 trustcache");
    free((void *)changed.cryptex_trustcache.data);

    /* (8b) A second module that pushes the reservation over a page boundary.
     * Apple's own sizes do not: 12 + 91416 + 3144 still rounds to six pages
     * with or without the cryptex module, so a reservation that forgot the
     * second module would be invisible there. 12 + 16370 is 16382, one page,
     * and 68 more bytes is two. */
    changed = in;
    changed.trustcache_v2 = false;
    changed.trustcache = cx_module(1, 743, 24 + 743 * 22);
    changed.cryptex_trustcache = cx_module(1, 2, 24 + 2 * 22);
    cx_accepted("cryptex crosses a page boundary", &changed, &two);
    cx_catalog("cryptex crosses a page boundary", &two, 2, 16370, 68);
    if (cx_region(&two)->size != 2 * APPLE_MODERN_PAGE_SIZE) {
        fprintf(stderr, "FAIL the page-crossing case reserves 0x%" PRIx64 "\n",
                cx_region(&two)->size);
        exit(1);
    }
    cx_checks++;
    free((void *)changed.trustcache.data);
    free((void *)changed.cryptex_trustcache.data);

    /* (9) Apple's own geometry: 3,808 static entries plus 130 cryptex
     * entries. 4 + 8 + 91416 + 3144 = 94572 bytes, which is 6 pages. */
    changed = in;
    changed.trustcache = cx_module(2, 3808, 24 + 3808 * 24);
    changed.cryptex_trustcache = cx_module(2, 130, 24 + 130 * 24);
    cx_accepted("Apple static + Apple OS cryptex", &changed, &two);
    cx_catalog("Apple static + Apple OS cryptex", &two, 2, 91416, 3144);
    if (cx_region(&two)->size != 6 * APPLE_MODERN_PAGE_SIZE) {
        fprintf(stderr, "FAIL Apple geometry reserves 0x%" PRIx64 "\n",
                cx_region(&two)->size);
        exit(1);
    }
    cx_checks++;
    free((void *)changed.trustcache.data);
    free((void *)changed.cryptex_trustcache.data);

    free((void *)in.bootkc.data);
    free((void *)in.sptm.data);
    free((void *)in.txm.data);
    free((void *)in.dtree.data);
    free((void *)in.trustcache.data);
}

static void actual(const char *directory)
{
    char path[4096];
    AppleModernBootInput in = { .dram_base = UINT64_C(1) << 40,
                               .dram_size = UINT64_C(8) << 30,
                               .trustcache_v2 = true };
    AppleModernBootLayout out;
    const AppleModernBootCopy *copy[2];

    assert(snprintf(path, sizeof(path), "%s/os-cryptex-trustcache", directory) <
           (int)sizeof(path));
    if (access(path, R_OK)) {
        printf("SKIP os-cryptex-trustcache is absent from %s\n", directory);
        return;
    }
    assert(snprintf(path, sizeof(path), "%s/static-trustcache", directory) <
           (int)sizeof(path));
    if (access(path, R_OK)) {
        printf("SKIP static-trustcache is absent from %s\n", directory);
        return;
    }
    in.bootkc = file(directory, "bootkc");
    in.sptm = file(directory, "sptm");
    in.txm = file(directory, "txm");
    in.dtree = file(directory, "dtree");
    in.trustcache = file(directory, "static-trustcache");
    in.cryptex_trustcache = file(directory, "os-cryptex-trustcache");
    cx_accepted("Apple's own two modules", &in, &out);
    cx_catalog("Apple's own two modules", &out, 2, in.trustcache.size,
               in.cryptex_trustcache.size);
    cx_copies(&out, copy);
    printf("ACTUAL static v%u entries=%u bytes=%zu at 0x%016" PRIx64
           "; cryptex v%u entries=%u bytes=%zu at 0x%016" PRIx64 "\n",
           cx_le32(in.trustcache.data), cx_le32(in.trustcache.data + 20),
           in.trustcache.size, copy[0]->physical_address,
           cx_le32(in.cryptex_trustcache.data),
           cx_le32(in.cryptex_trustcache.data + 20),
           in.cryptex_trustcache.size, copy[1]->physical_address);
    cx_checks++;
    free((void *)in.bootkc.data);
    free((void *)in.sptm.data);
    free((void *)in.txm.data);
    free((void *)in.dtree.data);
    free((void *)in.trustcache.data);
    free((void *)in.cryptex_trustcache.data);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (layout_regression_main(1, argv)) {
        return 1;
    }
    cryptex();
    if (argc == 2) {
        actual(argv[1]);
    }
    printf("PASS %u cryptex-trustcache checks (+%u shared layout checks); "
           "preparation only, no guest execution\n", cx_checks, checks);
    return 0;
}
