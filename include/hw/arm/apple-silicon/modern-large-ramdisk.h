/*
 * Opt-in host-file mapping for a multi-gigabyte modern Apple ramdisk.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * The normal asset path (read_asset() in modern-machine.c) reads a whole file
 * into host anonymous memory and refuses anything over 512 MiB. A restored
 * iOS system volume is ~9.4 GiB, which neither fits that cap nor the host.
 *
 * This unit maps such a file instead of copying it:
 *   - the file is opened O_RDONLY and is never written, so a distribution
 *     image can not be modified through this path;
 *   - the mapping is MAP_PRIVATE, so guest stores become host copy-on-write
 *     pages and still never reach the file;
 *   - peak host anonymous memory is therefore the number of pages the guest
 *     actually dirties, not the file size. Clean pages stay reclaimable page
 *     cache.
 *
 * Declared limits (not measured fidelity claims):
 *   - the file is mapped lazily, so the fstat-before/after equality check
 *     proves only that the file did not change between open and mapping. A
 *     host write to the file afterwards is visible to the guest in any page
 *     that has not been faulted in yet. Keep the image immutable while a
 *     guest runs.
 *   - the mapping is not registered for migration.
 */
#ifndef HW_ARM_APPLE_MODERN_LARGE_RAMDISK_H
#define HW_ARM_APPLE_MODERN_LARGE_RAMDISK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * For Error (QEMU's or the standalone test adapter) and the shared
 * APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE ceiling. The strict 512 MiB per-asset
 * and 1 GiB total budgets in modern-machine.c are unchanged for every other
 * asset.
 */
#include "hw/arm/apple-silicon/modern-boot-layout.h"

typedef struct AppleModernLargeRamdisk {
    /* Mapping base; readable and privately writable, never written back. */
    uint8_t *host;
    /* Mapped length: file_size rounded up to the mapping alignment. */
    uint64_t map_size;
    /* Bytes the file held when it was mapped. */
    uint64_t file_size;
} AppleModernLargeRamdisk;

/*
 * Map `path` read-only and privately. Refuses a symlink, a non-regular file,
 * an empty file, a file larger than APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE, and
 * a file that changed between the two fstat calls. On failure *out is zeroed
 * and nothing is mapped.
 */
bool apple_modern_large_ramdisk_map(const char *path,
                                    AppleModernLargeRamdisk *out,
                                    Error **errp);

/*
 * Declared in-memory edits of a mapped ramdisk (machine option
 * ramdisk-patches). The list file holds one patch per line:
 *     <offset> <old-hex> <new-hex>    # optional comment
 * offset is a byte offset into the image (C syntax, 0x prefix for hex); old
 * and new are hex strings of equal length, at most
 * APPLE_MODERN_RAMDISK_PATCH_MAX bytes. Every line is checked against the
 * mapped bytes before any is written (a line whose bytes already equal the new
 * value is accepted), so a stale list changes nothing. Writes land in the
 * private copy-on-write mapping only: the image file is never modified.
 */
#define APPLE_MODERN_RAMDISK_PATCH_MAX 512u
#define APPLE_MODERN_RAMDISK_PATCH_LINES 256u
bool apple_modern_large_ramdisk_patch(AppleModernLargeRamdisk *map,
                                      const char *path, unsigned *applied,
                                      Error **errp);

/*
 * Declared in-memory splice of one whole region of a mapped ramdisk (machine
 * option ramdisk-splice), for edits far larger than a ramdisk-patches line can
 * carry (512 bytes x 256 lines). The spec is
 *     <offset>:<blob-path>:<fnv1a64-of-the-original-region>
 * The blob's own length defines the region length, so a splice can never grow
 * or shrink the image. The FNV-1a-64 digest of the bytes currently mapped at
 * <offset> is verified against the declared value before anything is written;
 * a region that already equals the blob is accepted (idempotent re-run). The
 * digest guards against splicing a stale or wrong image, not against a
 * tampering adversary, so a compact self-contained hash is used rather than
 * pulling a crypto dependency into the standalone layout test build. As with
 * ramdisk-patches, writes land in the private copy-on-write mapping only and
 * the image file is never modified.
 *
 * Used to deliver an edited launch-service cache: iOS launchd reads the binary
 * plist cache, NOT the on-disk LaunchDaemon plists, so EnvironmentVariables
 * added to a .plist in the image never reach the job. The cache is ~2.4 MB, far
 * past the per-line patch ceiling, and a binary plist cannot be edited in place
 * because its object and offset tables shift.
 */
bool apple_modern_large_ramdisk_splice(AppleModernLargeRamdisk *map,
                                       const char *spec, Error **errp);

/* Release the mapping. Safe on an all-zero struct; zeroes *map. */
void apple_modern_large_ramdisk_unmap(AppleModernLargeRamdisk *map);

#endif /* HW_ARM_APPLE_MODERN_LARGE_RAMDISK_H */
