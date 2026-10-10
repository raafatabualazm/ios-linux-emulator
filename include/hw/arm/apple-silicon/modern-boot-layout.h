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
#define APPLE_MODERN_BOOTARGS_SIZE 1152
#define APPLE_MODERN_MAX_RAMDISK_SIZE (UINT64_C(4) << 30)
/*
 * Ceiling for the opt-in mapped ramdisk path only (AppleModernBootInput
 * large_ramdisk). The 4 GiB limit above still applies to the copying path,
 * as do the 512 MiB per-asset and 1 GiB total budgets in modern-machine.c.
 */
#define APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE (UINT64_C(32) << 30)
#define APPLE_MODERN_MAX_FRAMEBUFFER_DIMENSION 4096U
#define APPLE_MODERN_MAX_FRAMEBUFFER_SIZE (UINT64_C(64) << 20)
#define APPLE_MODERN_FRAMEBUFFER_ALIGNMENT (UINT64_C(2) << 20)

typedef enum AppleModernImage {
    APPLE_MODERN_BOOTKC,
    APPLE_MODERN_SPTM,
    APPLE_MODERN_TXM,
    APPLE_MODERN_TRUSTCACHE,
    APPLE_MODERN_RAMDISK,
} AppleModernImage;

typedef struct AppleModernBlob {
    const uint8_t *data;
    size_t size;
} AppleModernBlob;

typedef struct AppleModernBootInput {
    AppleModernBlob bootkc, sptm, txm, dtree, trustcache;
    /*
     * Optional second trust-cache module, published behind the same iBoot
     * catalog offsets header as the first. Absent (NULL/0) keeps the
     * single-module catalog every earlier revision produced.
     *
     * Why a second module exists at all: on a real device the OS cryptex is
     * grafted by libignition inside dyld, which then loads that cryptex's own
     * trust cache before it looks for the dyld shared cache. A board that
     * presents the cryptex's content without grafting it has no one to load
     * that module, so the loader publishes it instead. TXM's own diagnostic
     * is plural -- "loaded external trust cache modules: %u/%u".
     */
    AppleModernBlob cryptex_trustcache;
    /* Optional decoded bytes; matching provenance is the caller's job. */
    AppleModernBlob ramdisk;
    uint64_t dram_base;
    uint64_t dram_size;
    /* Optional 32-bit XRGB boot console; all zero disables the reservation.
     * A zero stride with nonzero width/height selects width * 4 bytes.
     */
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint32_t framebuffer_stride;
    /*
     * Declared opt-in: the ramdisk bytes are a host file mapping owned by the
     * caller, not a copied buffer, so the reservation may exceed
     * APPLE_MODERN_MAX_RAMDISK_SIZE up to
     * APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE. The layout is otherwise identical;
     * the caller is responsible for getting the bytes into guest RAM.
     */
    bool large_ramdisk;
    /* Opt-in: also accept a version-2 trustcache module (24-byte entries).
     * False keeps the version-1-only acceptance of every earlier revision.
     */
    bool trustcache_v2;
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
    uint64_t ramdisk_physical;
    uint64_t ramdisk_size;
    uint64_t framebuffer_physical;
    uint64_t framebuffer_size;
    uint64_t image_virtual_base[3];
    uint64_t image_entry_virtual[3];
    /*
     * Existing catalog bytes follow this ordinary iBoot offsets header:
     * uint32 module count, then that many uint32 byte offsets from the start
     * of the TrustCache region. One module therefore uses 8 bytes and two use
     * 12; trustcache_header_size says which, and the trailing bytes are zero.
     */
    uint8_t trustcache_offsets_header[12];
    uint32_t trustcache_header_size;
    uint32_t trustcache_module_count;
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
 * A nonempty version-1 trustcache is required, or a version-2 one when
 * trustcache_v2 is set; either way the module's own bytes are reserved
 * unchanged behind the catalog offsets header and no entry is parsed.
 * Optional ramdisk bytes are
 * reserved unchanged after BootArgs; no trustcache is fabricated.
 * An optional framebuffer is rounded to 2 MiB and carved out of the DRAM tail
 * as PurpleGfxMem, outside the boot-data area. top_of_kernel_data is unchanged.
 * The metadata consumer retargets it after MTE's usable-memory adjustment and
 * excludes it from boot_args.memSize. It is never an image-copy source.
 * DeviceTree reserves 64 KiB of bounded slack for
 * the consumer's normal boot metadata; the original ADT is not altered here.
 * The consumer must serialize/check its working ADT before copying anything
 * and must implement CPU/platform devices before using this execution plan.
 * DRAM must start at 1 TiB and fit within this layout's 36-bit index window.
 * Output must not overlap input structs/blobs. On forbidden aliases it is
 * untouched, preserving the input; other failures clear it.
 */
bool apple_modern_boot_layout_build(const AppleModernBootInput *input,
                                   AppleModernBootLayout *output,
                                   Error **errp);

#endif
