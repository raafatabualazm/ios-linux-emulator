/*
 * Strict modern Apple boot layout, preparation only.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef HW_ARM_APPLE_MODERN_BOOT_LAYOUT_H
#define HW_ARM_APPLE_MODERN_BOOT_LAYOUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
/* Test adapter only; production uses QEMU's Error implementation. */
typedef struct Error { char message[256]; } Error;
void error_free(Error *error);
#else
#include "qapi/error.h"
#endif

#define APPLE_MODERN_PAGE_SIZE UINT64_C(0x4000)
#define APPLE_MODERN_MAX_REGIONS 24
#define APPLE_MODERN_MAX_COPIES 32
#define APPLE_MODERN_DT_SLACK UINT64_C(0x10000)
#define APPLE_MODERN_BOOTARGS_SIZE 1160

typedef enum AppleModernImage {
    APPLE_MODERN_BOOTKC,
    APPLE_MODERN_SPTM,
    APPLE_MODERN_TXM,
    APPLE_MODERN_TRUSTCACHE,
} AppleModernImage;

typedef struct AppleModernBlob {
    const uint8_t *data;
    size_t size;
} AppleModernBlob;

typedef struct AppleModernBootInput {
    AppleModernBlob bootkc, sptm, txm, dtree, trustcache;
    uint64_t dram_base;
    uint64_t dram_size;
} AppleModernBootInput;

typedef struct AppleModernBootRegion {
    /* Names are ADT memory-map entries, not host page protection policies. */
    char name[24];
    uint64_t physical_address;
    uint64_t size;
} AppleModernBootRegion;

typedef struct AppleModernBootCopy {
    AppleModernImage image;
    char segment[17];
    uint64_t source_offset;
    uint64_t file_size;
    uint64_t physical_address;
    uint64_t memory_size;
} AppleModernBootCopy;

typedef struct AppleModernBootLayout {
    AppleModernBootRegion regions[APPLE_MODERN_MAX_REGIONS];
    AppleModernBootCopy copies[APPLE_MODERN_MAX_COPIES];
    size_t region_count, copy_count;
    uint64_t dram_base, dram_size;
    uint64_t virtual_base;
    uint64_t sptm_entry_physical;
    uint64_t bootargs_physical;
    uint64_t dtree_physical;
    uint64_t dtree_capacity;
    uint64_t top_of_kernel_data;
    uint64_t image_virtual_base[3];
    uint64_t image_entry_virtual[3];
    /* Existing catalog bytes follow this ordinary iBoot offsets header. */
    uint8_t trustcache_offsets_header[8];
    uint32_t dtree_node_count;
    uint32_t fileset_entry_count;
    char platform[16];
} AppleModernBootLayout;

/*
 * Validate raw, decoded components and describe segment copies, zero-fill
 * extents and reserved metadata regions for the T8140 SPTM layout. Output is
 * cleared on failure. Never writes
 * input blobs or guest memory, patches executable bytes, registers a board,
 * selects a CPU, or starts guest execution. Does not verify signatures.
 *
 * A nonempty version-1 trustcache is required. There is no ramdisk input and
 * no fabricated trustcache. DeviceTree reserves 64 KiB of bounded slack for
 * the consumer's normal boot metadata; the original ADT is not altered here.
 * The consumer must serialize/check its working ADT before copying anything
 * and must implement CPU/platform devices before using this execution plan.
 * DRAM must start at 1 TiB and fit within this layout's 36-bit index window.
 */
bool apple_modern_boot_layout_build(const AppleModernBootInput *input,
                                   AppleModernBootLayout *output,
                                   Error **errp);

#endif
