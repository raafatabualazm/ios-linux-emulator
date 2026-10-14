/*
 * Opt-in host-file mapping for a multi-gigabyte modern Apple ramdisk.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hw/arm/apple-silicon/modern-large-ramdisk.h"

/* The guest page size the boot layout rounds ramdisk reservations to. */
#define LARGE_RAMDISK_ALIGNMENT UINT64_C(0x4000)

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
static void error_setg(Error **errp, const char *format, ...)
{
    va_list args;
    if (!errp) {
        return;
    }
    if (*errp) {
        abort();
    }
    *errp = calloc(1, sizeof(**errp));
    if (!*errp) {
        abort();
    }
    va_start(args, format);
    vsnprintf((*errp)->message, sizeof((*errp)->message), format, args);
    va_end(args);
}
#endif

static bool fail(Error **errp, const char *message, const char *path)
{
    error_setg(errp, "%s: %s", message, path);
    return false;
}

static bool same_file(const struct stat *a, const struct stat *b)
{
    return a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec &&
           a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static uint64_t round_up(uint64_t value, uint64_t alignment)
{
    /* Callers bound value well below UINT64_MAX - alignment. */
    return (value + alignment - 1) & ~(alignment - 1);
}

bool apple_modern_large_ramdisk_map(const char *path,
                                    AppleModernLargeRamdisk *out,
                                    Error **errp)
{
    struct stat before, after;
    uint64_t alignment, host_page, map_size, file_pages;
    void *base, *fixed;
    int fd;

    if (!out) {
        error_setg(errp, "missing large ramdisk output");
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!path) {
        error_setg(errp, "missing large ramdisk path");
        return false;
    }
    host_page = (uint64_t)sysconf(_SC_PAGESIZE);
    if (!host_page || (host_page & (host_page - 1))) {
        error_setg(errp, "unusable host page size");
        return false;
    }
    alignment = host_page > LARGE_RAMDISK_ALIGNMENT ? host_page
                                                    : LARGE_RAMDISK_ALIGNMENT;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        error_setg(errp, "cannot open large modern ramdisk %s: %s", path,
                   strerror(errno));
        return false;
    }
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_size <= 0 ||
        (uint64_t)before.st_size > APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE) {
        error_setg(errp, "large modern ramdisk must be a regular nonempty "
                   "file of at most %" PRIu64 " bytes: %s",
                   APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE, path);
        close(fd);
        return false;
    }
    map_size = round_up((uint64_t)before.st_size, alignment);
    /*
     * Reserve the whole rounded span first, then map the file over the pages
     * it actually backs. Whole host pages past end-of-file would SIGBUS, so
     * the tail of the last guest page comes from the anonymous reservation
     * (it reads as zero, exactly as the copying path's page rounding did).
     */
    base = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (base == MAP_FAILED) {
        error_setg(errp, "cannot reserve %" PRIu64 " bytes for %s: %s",
                   map_size, path, strerror(errno));
        close(fd);
        return false;
    }
    file_pages = round_up((uint64_t)before.st_size, host_page);
    if (file_pages > map_size) {
        file_pages = map_size;
    }
    /*
     * PROT_WRITE on a MAP_PRIVATE mapping of a read-only descriptor is
     * allowed and gives copy-on-write: the guest may write, the file can not.
     */
    fixed = mmap(base, file_pages, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (fixed != base) {
        error_setg(errp, "cannot map %" PRIu64 " bytes of %s: %s", file_pages,
                   path, strerror(errno));
        if (fixed != MAP_FAILED) {
            munmap(fixed, file_pages);
        }
        munmap(base, map_size);
        close(fd);
        return false;
    }
    if (fstat(fd, &after) || !same_file(&before, &after)) {
        munmap(base, map_size);
        close(fd);
        return fail(errp, "large modern ramdisk changed while mapping", path);
    }
    close(fd);
    out->host = base;
    out->map_size = map_size;
    out->file_size = (uint64_t)before.st_size;
    return true;
}

void apple_modern_large_ramdisk_unmap(AppleModernLargeRamdisk *map)
{
    if (!map) {
        return;
    }
    if (map->host && map->map_size) {
        munmap(map->host, map->map_size);
    }
    memset(map, 0, sizeof(*map));
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Decode an even-length hex token into out[]; returns the byte count or -1. */
static long hex_decode(const char *token, uint8_t *out, size_t cap)
{
    size_t len = strlen(token);

    if (!len || (len & 1) || len / 2 > cap) {
        return -1;
    }
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_nibble(token[2 * i]);
        int lo = hex_nibble(token[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return (long)(len / 2);
}

bool apple_modern_large_ramdisk_patch(AppleModernLargeRamdisk *map,
                                      const char *path, unsigned *applied,
                                      Error **errp)
{
    uint8_t old_bytes[APPLE_MODERN_RAMDISK_PATCH_MAX];
    uint8_t new_bytes[APPLE_MODERN_RAMDISK_PATCH_MAX];
    char line[4 * APPLE_MODERN_RAMDISK_PATCH_MAX + 256];
    unsigned count = 0, lineno = 0;
    FILE *file;

    *applied = 0;
    if (!map || !map->host || !path) {
        error_setg(errp, "ramdisk patches need a mapped large ramdisk");
        return false;
    }
    file = fopen(path, "r");
    if (!file) {
        error_setg(errp, "cannot open ramdisk patch list %s: %s", path,
                   strerror(errno));
        return false;
    }
    /* Verify every line before writing any, so a bad list changes nothing. */
    for (int pass = 0; pass < 2; pass++) {
        rewind(file);
        lineno = 0;
        count = 0;
        while (fgets(line, sizeof(line), file)) {
            char offset_tok[32], old_tok[2 * APPLE_MODERN_RAMDISK_PATCH_MAX + 2];
            char new_tok[2 * APPLE_MODERN_RAMDISK_PATCH_MAX + 2];
            char *hash = strchr(line, '#');
            unsigned long long offset;
            long old_len, new_len;
            char *end;

            lineno++;
            if (!strchr(line, '\n') && !feof(file)) {
                error_setg(errp, "%s:%u: line too long", path, lineno);
                goto fail;
            }
            if (hash) {
                *hash = '\0';
            }
            if (sscanf(line, "%31s", offset_tok) != 1) {
                continue;  /* blank or comment-only line */
            }
            if (sscanf(line, "%31s %1025s %1025s", offset_tok, old_tok,
                       new_tok) != 3) {
                error_setg(errp, "%s:%u: expected <offset> <old-hex> <new-hex>",
                           path, lineno);
                goto fail;
            }
            errno = 0;
            offset = strtoull(offset_tok, &end, 0);
            old_len = hex_decode(old_tok, old_bytes, sizeof(old_bytes));
            new_len = hex_decode(new_tok, new_bytes, sizeof(new_bytes));
            if (errno || *end || old_len < 0 || new_len != old_len) {
                error_setg(errp, "%s:%u: bad offset or hex (old and new must be "
                           "the same length, at most %u bytes)", path, lineno,
                           APPLE_MODERN_RAMDISK_PATCH_MAX);
                goto fail;
            }
            if (offset > map->file_size || (uint64_t)old_len > map->file_size - offset) {
                error_setg(errp, "%s:%u: 0x%llx+%ld is outside the %" PRIu64
                           "-byte ramdisk", path, lineno, offset, old_len,
                           map->file_size);
                goto fail;
            }
            if (pass == 0 && memcmp(map->host + offset, old_bytes, old_len) &&
                memcmp(map->host + offset, new_bytes, old_len)) {
                error_setg(errp, "%s:%u: bytes at 0x%llx do not match the "
                           "expected old value", path, lineno, offset);
                goto fail;
            }
            if (++count > APPLE_MODERN_RAMDISK_PATCH_LINES) {
                error_setg(errp, "%s: more than %u patches", path,
                           APPLE_MODERN_RAMDISK_PATCH_LINES);
                goto fail;
            }
            if (pass == 1) {
                memcpy(map->host + offset, new_bytes, old_len);
            }
        }
        if (ferror(file)) {
            error_setg(errp, "error reading %s", path);
            goto fail;
        }
    }
    fclose(file);
    *applied = count;
    return true;

fail:
    fclose(file);
    return false;
}
