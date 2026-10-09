/* Core gate for the opt-in mapped large-ramdisk path (no QEMU, no guest).
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Exercises the production sources unchanged:
 *   hw/arm/apple-silicon/modern-large-ramdisk.c  (open/fstat/mmap policy)
 *   hw/arm/apple-silicon/modern-boot-layout.c    (the two ramdisk size caps)
 *
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *    hw/arm/apple-silicon/modern-large-ramdisk.c \
 *    hw/arm/apple-silicon/modern-boot-layout.c \
 *    scripts/test-apple-modern-large-ramdisk.c -o /tmp/test-modern-large-ramdisk
 *
 * argv[1] is a writable scratch directory (the harness supplies one).
 */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "hw/arm/apple-silicon/modern-boot-layout.h"
#include "hw/arm/apple-silicon/modern-large-ramdisk.h"

#define PAGE 0x4000U
static unsigned checks;

static void ok(bool condition, const char *what)
{
    if (!condition) {
        fprintf(stderr, "FAIL %s\n", what);
        exit(1);
    }
    checks++;
}

static void put32(uint8_t *p, uint32_t x)
{
    for (unsigned i = 0; i < 4; i++) { p[i] = x >> (8 * i); }
}

static void put64(uint8_t *p, uint64_t x)
{
    put32(p, x); put32(p + 4, x >> 32);
}

/* ---------------------------------------------------------------- fixtures */

static char *join(const char *dir, const char *name)
{
    size_t len = strlen(dir) + strlen(name) + 2;
    char *path = malloc(len);
    assert(path);
    snprintf(path, len, "%s/%s", dir, name);
    return path;
}

/* Writes `size` bytes whose value at offset i is a function of i, so a later
 * comparison cannot pass on an all-zero or wrong-file mapping. */
static void write_pattern(const char *path, uint64_t size, uint8_t seed)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    uint8_t *buffer = malloc(0x10000);
    uint64_t done = 0;
    assert(fd >= 0 && buffer);
    while (done < size) {
        uint64_t chunk = size - done < 0x10000 ? size - done : 0x10000;
        for (uint64_t i = 0; i < chunk; i++) {
            buffer[i] = (uint8_t)((done + i) * 31u + seed);
        }
        ok(write(fd, buffer, chunk) == (ssize_t)chunk, "fixture write");
        checks--; /* fixture bookkeeping is not a semantic check */
        done += chunk;
    }
    free(buffer);
    close(fd);
}

static bool pattern_matches(const uint8_t *host, uint64_t size, uint8_t seed)
{
    for (uint64_t i = 0; i < size; i++) {
        if (host[i] != (uint8_t)(i * 31u + seed)) {
            return false;
        }
    }
    return true;
}

static void refuse_map(const char *path, const char *what)
{
    AppleModernLargeRamdisk map;
    Error *err = NULL;
    memset(&map, 0x5a, sizeof(map));
    ok(!apple_modern_large_ramdisk_map(path, &map, &err), what);
    ok(err && err->message[0], "refusal carries a message");
    ok(!map.host && !map.map_size && !map.file_size, "output zeroed on refusal");
    printf("REJECT %s: %s\n", what, err->message);
    error_free(err);
}

/* ------------------------------------------------------- mapping behaviour */

static void mapping_cases(const char *dir)
{
    AppleModernLargeRamdisk map;
    Error *err = NULL;
    char *exact = join(dir, "exact.bin");
    char *odd = join(dir, "odd.bin");
    char *empty = join(dir, "empty.bin");
    char *link = join(dir, "link.bin");
    char *huge = join(dir, "huge.bin");
    char *missing = join(dir, "missing.bin");
    struct stat before, after;
    uint8_t probe;
    int fd;

    /* 1. A file that is an exact multiple of the 16 KiB guest page. */
    write_pattern(exact, 4 * PAGE, 7);
    ok(apple_modern_large_ramdisk_map(exact, &map, &err), "exact-size map");
    ok(!err, "no error on success");
    ok(map.file_size == 4 * PAGE, "file_size is the file size");
    ok(map.map_size == 4 * PAGE, "map_size needs no rounding");
    ok(pattern_matches(map.host, map.file_size, 7), "mapped bytes equal file");
    /* A private store is visible to this process and never reaches the file. */
    map.host[1234] = 0xa5;
    ok(map.host[1234] == 0xa5, "mapping is privately writable");
    fd = open(exact, O_RDONLY);
    ok(fd >= 0 && pread(fd, &probe, 1, 1234) == 1, "re-read the file");
    ok(probe == (uint8_t)(1234u * 31u + 7u), "the file itself is unchanged");
    close(fd);
    apple_modern_large_ramdisk_unmap(&map);
    ok(!map.host && !map.map_size && !map.file_size, "unmap zeroes the struct");

    /* 2. A size that is not a multiple of the guest page: the reservation is
     *    rounded up and the bytes past end-of-file read as zero, exactly as
     *    the copying path's page-rounded region did. */
    write_pattern(odd, 3 * PAGE + 101, 19);
    ok(apple_modern_large_ramdisk_map(odd, &map, &err), "odd-size map");
    ok(map.file_size == 3 * PAGE + 101, "odd file_size");
    ok(map.map_size == 4 * PAGE, "map_size rounds up to the guest page");
    ok(pattern_matches(map.host, map.file_size, 19), "odd mapped bytes");
    for (uint64_t i = map.file_size; i < map.map_size; i++) {
        if (map.host[i]) {
            ok(false, "tail past end-of-file reads as zero");
        }
    }
    ok(true, "tail past end-of-file reads as zero");
    apple_modern_large_ramdisk_unmap(&map);

    /* 3. Two mappings of the same file are independent (no shared dirtying). */
    {
        AppleModernLargeRamdisk second;
        ok(apple_modern_large_ramdisk_map(odd, &map, &err), "first mapping");
        ok(apple_modern_large_ramdisk_map(odd, &second, &err), "second mapping");
        map.host[7] = 0x11;
        ok(second.host[7] == (uint8_t)(7u * 31u + 19u),
           "private store is not visible in another mapping");
        apple_modern_large_ramdisk_unmap(&map);
        apple_modern_large_ramdisk_unmap(&second);
    }

    /* 4. Refusals. */
    fd = open(empty, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ok(fd >= 0, "created an empty fixture");
    checks--;
    close(fd);
    refuse_map(empty, "empty file");
    refuse_map(dir, "directory");
    refuse_map(missing, "missing path");
    ok(symlink(exact, link) == 0, "created a symlink fixture");
    checks--;
    refuse_map(link, "symlink (O_NOFOLLOW)");
    /* A sparse file one byte over the opt-in ceiling: refused on st_size
     * before anything is mapped, so it costs no memory and no disk. */
    fd = open(huge, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ok(fd >= 0 && !ftruncate(fd, (off_t)APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE + 1),
       "created an oversize sparse fixture");
    checks--;
    close(fd);
    refuse_map(huge, "file over the opt-in ceiling");
    refuse_map(NULL, "NULL path");
    {
        Error *e = NULL;
        ok(!apple_modern_large_ramdisk_map(exact, NULL, &e), "NULL output");
        ok(e && e->message[0], "NULL output carries a message");
        error_free(e);
    }

    /* 5. The anti-TOCTOU check: a file replaced between the two fstat calls
     *    cannot be detected from this process, but a file whose metadata
     *    differs is. Prove the comparison the production code uses actually
     *    distinguishes a rewritten file (same size, new mtime). */
    ok(!stat(exact, &before), "stat before rewrite");
    checks--;
    write_pattern(exact, 4 * PAGE, 23);
    ok(!stat(exact, &after), "stat after rewrite");
    checks--;
    ok(before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
       before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
       before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
       before.st_ctim.tv_nsec != after.st_ctim.tv_nsec,
       "rewriting a same-size file changes the compared metadata");
    ok(apple_modern_large_ramdisk_map(exact, &map, &err), "remap after rewrite");
    ok(pattern_matches(map.host, map.file_size, 23), "remap sees new bytes");
    apple_modern_large_ramdisk_unmap(&map);

    unlink(link); unlink(huge); unlink(empty); unlink(odd); unlink(exact);
    free(exact); free(odd); free(empty); free(link); free(huge); free(missing);
}

/* --------------------------------------------------------- layout size cap */

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
        put32(d + cursor + 24, 32);
        strcpy((char *)d + cursor + 32, "com.apple.kernel");
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
    static const char *const b[] = {"__TEXT_EXEC", "__TEXT_BOOT_EXEC", "__TEXT",
        "__PRELINK_TEXT", "__DATA_CONST", "__DATA_SPTM", "__PRELINK_INFO",
        "__DATA", "__LINKEDIT"};
    static const char *const s[] = {"__TEXT", "__DATA_CONST", "__LATE_CONST",
        "__TEXT_EXEC", "__LAST", "__DATA", "__BOOTDATA", "__LINKEDIT"};
    static const char *const t[] = {"__TEXT", "__DATA_CONST", "__TEXT_EXEC",
        "__TEXT_BOOT_EXEC", "__DATA", "__LINKEDIT"};
    uint8_t *dt = calloc(1, 1024), *tc = calloc(1, 46);
    size_t p = 8;
    AppleModernBootInput in = { .dram_base = UINT64_C(1) << 40,
                               .dram_size = UINT64_C(24) << 30 };
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
    ok(!apple_modern_boot_layout_build(input, &out, &err), name);
    ok(err && err->message[0], "layout refusal carries a message");
    ok(!memcmp(&out, &zero, sizeof(out)), "layout output zeroed on refusal");
    printf("REJECT %s: %s\n", name, err->message);
    error_free(err);
}

/*
 * The layout never dereferences the ramdisk blob (only its size and, for the
 * alias guard, the pointer value), so the size cases below declare a size far
 * larger than the one-page buffer they point at. That is checked here by
 * asserting the recorded reservation is the declared size, not the buffer's.
 */
static void layout_cases(void)
{
    AppleModernBootInput in = fixture(), changed;
    AppleModernBootLayout out;
    Error *err = NULL;
    uint8_t *stand_in = calloc(1, PAGE);
    uint64_t big = (UINT64_C(9) << 30) + 0x1234 * PAGE;
    size_t found;

    assert(stand_in);

    /* Baseline: no ramdisk at all. */
    ok(apple_modern_boot_layout_build(&in, &out, &err), "baseline layout");
    ok(!out.ramdisk_physical && !out.ramdisk_size, "no ramdisk reservation");

    /* Copying path: the 4 GiB cap is unchanged, including exactly at it. */
    changed = in;
    changed.ramdisk = (AppleModernBlob){stand_in,
                                        APPLE_MODERN_MAX_RAMDISK_SIZE + 1};
    rejected("copying path over 4 GiB", &changed);
    changed.ramdisk = (AppleModernBlob){stand_in, APPLE_MODERN_MAX_RAMDISK_SIZE};
    ok(apple_modern_boot_layout_build(&changed, &out, &err),
       "copying path exactly at 4 GiB");
    ok(out.ramdisk_size == APPLE_MODERN_MAX_RAMDISK_SIZE, "4 GiB reservation");

    /* Mapped path: a 9.4 GiB image is accepted and reserved page-rounded. */
    changed = in;
    changed.large_ramdisk = true;
    changed.ramdisk = (AppleModernBlob){stand_in, big};
    ok(apple_modern_boot_layout_build(&changed, &out, &err), "mapped 9+ GiB");
    ok(out.ramdisk_size == big, "reservation is the declared size");
    ok(out.ramdisk_physical && !(out.ramdisk_physical % PAGE),
       "ramdisk_physical is guest-page aligned");
    ok(out.ramdisk_physical >= out.dram_base, "ramdisk is inside DRAM");
    found = out.region_count;
    for (size_t i = 0; i < out.region_count; i++) {
        if (!strcmp(out.regions[i].name, "RAMDisk")) {
            found = i;
        }
    }
    ok(found < out.region_count, "a RAMDisk memory-map region exists");
    ok(out.regions[found].physical_address == out.ramdisk_physical,
       "region address equals ramdisk_physical");
    ok(out.regions[found].size == ((big + PAGE - 1) & ~(uint64_t)(PAGE - 1)),
       "region size is the page-rounded image size");
    ok(out.top_of_kernel_data >= out.ramdisk_physical + out.regions[found].size,
       "top_of_kernel_data covers the ramdisk");
    found = out.copy_count;
    for (size_t i = 0; i < out.copy_count; i++) {
        if (out.copies[i].image == APPLE_MODERN_RAMDISK) {
            found = i;
        }
    }
    ok(found < out.copy_count,
       "the copy entry is still emitted (the board skips it when mapped)");

    /* Mapped path: its own ceiling, and one byte over it. */
    changed.ramdisk = (AppleModernBlob){stand_in,
                                        APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE + 1};
    rejected("mapped path over its 32 GiB ceiling", &changed);

    /* The DRAM bound still applies on the mapped path. */
    changed.ramdisk = (AppleModernBlob){stand_in, big};
    changed.dram_size = UINT64_C(4) << 30;
    rejected("mapped ramdisk larger than DRAM", &changed);

    /* The empty/NULL consistency rule is unchanged by the flag. */
    changed = in;
    changed.large_ramdisk = true;
    changed.ramdisk = (AppleModernBlob){NULL, 1};
    rejected("mapped path with NULL bytes", &changed);
    changed.ramdisk = (AppleModernBlob){stand_in, 0};
    rejected("mapped path with zero size", &changed);

    free(stand_in);
    free((void *)in.bootkc.data); free((void *)in.sptm.data);
    free((void *)in.txm.data); free((void *)in.dtree.data);
    free((void *)in.trustcache.data);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s SCRATCH_DIR\n", argv[0]);
        return 2;
    }
    mapping_cases(argv[1]);
    layout_cases();
    printf("PASS %u semantic checks; mapping and layout only, "
           "no guest execution\n", checks);
    return 0;
}
