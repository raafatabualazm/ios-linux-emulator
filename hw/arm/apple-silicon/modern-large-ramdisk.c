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
