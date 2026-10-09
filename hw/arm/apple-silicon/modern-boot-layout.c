/*
 * Modern Apple boot preparation. No board or CPU execution is provided.
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
#include "hw/arm/apple-silicon/modern-boot-layout.h"

#define MAX_SEGMENTS 16
#define MAX_COMMANDS 4096
#define MAX_IMAGE_SIZE (UINT64_C(512) << 20)
#define MAX_DT_SIZE (UINT64_C(16) << 20)
#define VIRTUAL_INDEX_MASK ((UINT64_C(1) << 36) - 1)
#define SPTM_STRIDE UINT64_C(0x10000000)

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

void error_free(Error *error)
{
    free(error);
}
#endif

typedef struct Segment {
    char name[17];
    uint64_t va, size, offset, file_size;
    uint32_t protection;
} Segment;

typedef struct Image {
    AppleModernBlob blob;
    Segment segments[MAX_SEGMENTS];
    size_t count;
    uint64_t low, high, entry;
    uint32_t filesets;
} Image;

typedef struct DTree {
    AppleModernBlob blob;
    size_t cursor;
    uint32_t nodes;
    bool platform, cpu0;
} DTree;

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
    return le32(p) | (uint64_t)le32(p + 4) << 32;
}

static bool span(uint64_t offset, uint64_t size, uint64_t limit)
{
    return offset <= limit && size <= limit - offset;
}

static bool fail(Error **errp, const char *reason)
{
    error_setg(errp, "modern boot layout: %s", reason);
    return false;
}

static bool round_page(uint64_t value, uint64_t *rounded, Error **errp)
{
    if (value > UINT64_MAX - (APPLE_MODERN_PAGE_SIZE - 1)) {
        return fail(errp, "page-rounding overflow");
    }
    *rounded = (value + APPLE_MODERN_PAGE_SIZE - 1) &
               ~(APPLE_MODERN_PAGE_SIZE - 1);
    return true;
}

/* Validate a fileset child's complete command table before any pointer use. */
static bool child_header(AppleModernBlob blob, uint64_t offset, Error **errp)
{
    const uint8_t *h;
    uint64_t cursor, end;
    uint32_t count, bytes;
    if (!span(offset, 32, blob.size)) {
        return fail(errp, "fileset child header outside image");
    }
    h = blob.data + offset;
    count = le32(h + 16);
    bytes = le32(h + 20);
    if (le32(h) != 0xfeedfacf || le32(h + 4) != 0x0100000c ||
        (le32(h + 8) & 0xffffff) != 2 ||
        (le32(h + 12) != 2 && le32(h + 12) != 11) ||
        !count || count > MAX_COMMANDS || !span(offset + 32, bytes, blob.size)) {
        return fail(errp, "invalid fileset child Mach-O header");
    }
    cursor = offset + 32;
    end = cursor + bytes;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t size, cmd;
        if (!span(cursor, 8, end)) {
            return fail(errp, "truncated fileset child command");
        }
        cmd = le32(blob.data + cursor);
        size = le32(blob.data + cursor + 4);
        if (size < 8 || size % 8 || !span(cursor, size, end)) {
            return fail(errp, "invalid fileset child command bounds");
        }
        if (cmd == 0x19) {
            const uint8_t *s = blob.data + cursor;
            if (size < 72 || le32(s + 64) > (size - 72) / 80 ||
                size != 72 + (uint64_t)le32(s + 64) * 80 ||
                le64(s + 48) > le64(s + 32) ||
                !span(le64(s + 40), le64(s + 48), blob.size)) {
                return fail(errp, "fileset child segment outside image");
            }
        } else if (cmd == 0x21 || cmd == 0x2c) {
            const uint8_t *c = blob.data + cursor;
            if (cmd != 0x2c || size != 24 || le32(c + 16) ||
                !span(le32(c + 8), le32(c + 12), blob.size)) {
                return fail(errp, "encrypted or malformed fileset child");
            }
        }
        cursor += size;
    }
    if (cursor != end) {
        return fail(errp, "fileset child command count mismatch");
    }
    return true;
}

static bool parse_image(AppleModernBlob blob, uint32_t type, Image *image,
                        Error **errp)
{
    uint64_t cursor, end;
    uint32_t count, bytes;
    bool have_entry = false;
    if (!blob.data || blob.size < 32 || blob.size > MAX_IMAGE_SIZE) {
        return fail(errp, "image missing, truncated or too large");
    }
    if (le32(blob.data) != 0xfeedfacf ||
        le32(blob.data + 4) != 0x0100000c ||
        (le32(blob.data + 8) & 0xffffff) != 2 ||
        le32(blob.data + 12) != type) {
        return fail(errp, "expected ARM64e Mach-O image/file type");
    }
    count = le32(blob.data + 16);
    bytes = le32(blob.data + 20);
    if (!count || count > MAX_COMMANDS || !span(32, bytes, blob.size)) {
        return fail(errp, "Mach-O command table outside image");
    }
    image->blob = blob;
    image->low = UINT64_MAX;
    cursor = 32;
    end = cursor + bytes;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *c;
        uint32_t cmd, size;
        if (!span(cursor, 8, end)) {
            return fail(errp, "truncated Mach-O command");
        }
        c = blob.data + cursor;
        cmd = le32(c);
        size = le32(c + 4);
        if (size < 8 || size % 8 || !span(cursor, size, end)) {
            return fail(errp, "invalid Mach-O command bounds");
        }
        if (cmd == 0x19) {
            Segment *s;
            uint32_t sections;
            if (size < 72 || image->count == MAX_SEGMENTS) {
                return fail(errp, "truncated or excessive Mach-O segments");
            }
            sections = le32(c + 64);
            if (sections > (size - 72) / 80 ||
                size != 72 + (uint64_t)sections * 80) {
                return fail(errp, "Mach-O section table bounds mismatch");
            }
            s = &image->segments[image->count++];
            memcpy(s->name, c + 8, 16);
            s->va = le64(c + 24);
            s->size = le64(c + 32);
            s->offset = le64(c + 40);
            s->file_size = le64(c + 48);
            s->protection = le32(c + 60);
            if (!s->name[0] || !s->size ||
                s->va % APPLE_MODERN_PAGE_SIZE ||
                s->size % APPLE_MODERN_PAGE_SIZE ||
                s->offset % APPLE_MODERN_PAGE_SIZE ||
                s->file_size > s->size ||
                !span(s->offset, s->file_size, blob.size) ||
                s->size > UINT64_MAX - s->va ||
                (le32(c + 56) & ~7U) || (s->protection & ~7U) ||
                (s->protection & ~le32(c + 56))) {
                return fail(errp, "invalid Mach-O segment bounds/alignment/protection");
            }
            for (size_t j = 0; j + 1 < image->count; j++) {
                Segment *old = &image->segments[j];
                if (!strcmp(old->name, s->name) ||
                    (s->va < old->va + old->size && old->va < s->va + s->size)) {
                    return fail(errp, "duplicate/overlapping Mach-O segments");
                }
            }
            if (s->va < image->low) {
                image->low = s->va;
            }
            if (s->va + s->size > image->high) {
                image->high = s->va + s->size;
            }
        } else if (cmd == 5) {
            if (have_entry || size != 288 || le32(c + 8) != 6 ||
                le32(c + 12) != 68) {
                return fail(errp, "invalid/duplicate ARM64 thread entry");
            }
            image->entry = le64(c + 272);
            have_entry = true;
        } else if (cmd == 0x80000035) {
            uint32_t name;
            uint64_t offset;
            if (type != 12 || size < 40 || le32(c + 28)) {
                return fail(errp, "invalid fileset entry command");
            }
            name = le32(c + 24);
            offset = le64(c + 16);
            if (name < 32 || name >= size || !memchr(c + name, 0, size - name) ||
                offset < end || !child_header(blob, offset, errp)) {
                if (!errp || !*errp) {
                    return fail(errp, "invalid fileset child offset/name");
                }
                return false;
            }
            image->filesets++;
        } else if (cmd == 0x21 || cmd == 0x2c) {
            if (cmd != 0x2c || size != 24 || le32(c + 16) ||
                !span(le32(c + 8), le32(c + 12), blob.size)) {
                return fail(errp, "encrypted or malformed Mach-O image");
            }
        }
        cursor += size;
    }
    if (cursor != end || !image->count || !have_entry ||
        (type == 12 && !image->filesets)) {
        return fail(errp, "incomplete Mach-O segments/entry/fileset");
    }
    for (size_t i = 0; i < image->count; i++) {
        Segment *s = &image->segments[i];
        if ((s->protection & 4) && image->entry >= s->va &&
            image->entry - s->va < s->file_size && !(image->entry & 3)) {
            return true;
        }
    }
    return fail(errp, "Mach-O entry is outside file-backed executable code");
}

static bool parse_node(DTree *tree, const char *parent, unsigned depth,
                       Error **errp)
{
    const uint8_t *names[4096];
    char name[128] = "", path[512];
    uint32_t properties, children;
    size_t start;
    int path_length;
    if (depth > 32 || ++tree->nodes > 8192 ||
        !span(tree->cursor, 8, tree->blob.size)) {
        return fail(errp, "device tree node depth/count/bounds exceeded");
    }
    properties = le32(tree->blob.data + tree->cursor);
    children = le32(tree->blob.data + tree->cursor + 4);
    tree->cursor += 8;
    if (!properties || properties > 4096 || children > 8192) {
        return fail(errp, "invalid device tree node counts");
    }
    start = tree->cursor;
    for (uint32_t i = 0; i < properties; i++) {
        const uint8_t *p, *value;
        uint32_t length;
        uint64_t rounded;
        if (!span(tree->cursor, 36, tree->blob.size)) {
            return fail(errp, "truncated device tree property header");
        }
        p = tree->blob.data + tree->cursor;
        if (!p[0] || !memchr(p, 0, 32)) {
            return fail(errp, "invalid device tree property name");
        }
        for (uint32_t j = 0; j < i; j++) {
            if (!strcmp((const char *)names[j], (const char *)p)) {
                return fail(errp, "duplicate device tree property");
            }
        }
        names[i] = p;
        length = le32(p + 32) & 0x7fffffff;
        rounded = ((uint64_t)length + 3) & ~UINT64_C(3);
        tree->cursor += 36;
        if (!span(tree->cursor, rounded, tree->blob.size)) {
            return fail(errp, "device tree property outside blob");
        }
        value = tree->blob.data + tree->cursor;
        if (!strcmp((const char *)p, "name")) {
            const uint8_t *nul = memchr(value, 0, length);
            if (!nul || nul == value || (size_t)(nul - value) >= sizeof(name)) {
                return fail(errp, "invalid device tree node name");
            }
            memcpy(name, value, nul - value);
            if (depth && strchr(name, '/')) {
                return fail(errp, "device tree child name contains separator");
            }
        }
        tree->cursor += rounded;
    }
    path_length = snprintf(path, sizeof(path), "%s%s%s", parent,
                           depth ? "/" : "", depth ? name : "");
    if (!name[0] || path_length < 0 || (size_t)path_length >= sizeof(path)) {
        return fail(errp, "device tree path missing or too long");
    }
    /* Revisit only this bounded node's properties after its name is known. */
    for (uint32_t i = 0; i < properties; i++) {
        const uint8_t *p = tree->blob.data + start;
        uint32_t length = le32(p + 32) & 0x7fffffff;
        const uint8_t *value = p + 36;
        if (!strcmp(path, "/arm-io") && !strcmp((const char *)p, "compatible")) {
            static const char compatible[] = "arm-io,t8140";
            if (tree->platform || length < sizeof(compatible) ||
                memcmp(value, compatible, sizeof(compatible))) {
                return fail(errp, "unsupported or duplicate device tree platform");
            }
            tree->platform = true;
        }
        start += 36 + (((uint64_t)length + 3) & ~UINT64_C(3));
    }
    if (!strcmp(path, "/cpus/cpu0")) {
        if (tree->cpu0) {
            return fail(errp, "duplicate CPU0 device tree node");
        }
        tree->cpu0 = true;
    }
    for (uint32_t i = 0; i < children; i++) {
        if (!parse_node(tree, path, depth + 1, errp)) {
            return false;
        }
    }
    return true;
}

static Segment *segment(Image *image, const char *name)
{
    for (size_t i = 0; i < image->count; i++) {
        if (!strcmp(image->segments[i].name, name)) {
            return &image->segments[i];
        }
    }
    return NULL;
}

static bool push_copy(AppleModernBootLayout *out, Image *image,
                      AppleModernImage source, const char *name,
                      uint64_t *cursor, Error **errp)
{
    Segment *s = segment(image, name);
    AppleModernBootCopy *copy;
    uint64_t end = out->dram_base + out->dram_size;
    if (!s || out->copy_count == APPLE_MODERN_MAX_COPIES ||
        !span(*cursor, s ? s->size : 0, end)) {
        return fail(errp, "missing segment or copy exceeds DRAM");
    }
    copy = &out->copies[out->copy_count++];
    copy->image = source;
    strcpy(copy->segment, name);
    copy->source_offset = s->offset;
    copy->file_size = s->file_size;
    copy->physical_address = *cursor;
    copy->memory_size = s->size;
    *cursor += s->size;
    return true;
}

/*
 * Trust-cache module geometry only; no entry is read, compared, merged or
 * rewritten. The 24-byte module header is uint32 version, uuid[16], uint32
 * numEntries, followed by numEntries packed entries. A version-1 entry is
 * 22 bytes and a version-2 entry is 24 bytes; both start with the 20-byte
 * CDHash. Version 2 is accepted only when the caller opts in, so the default
 * board keeps refusing it exactly as before.
 *
 * `cryptex` only selects the wording, so a bad second module is not reported
 * as a bad first one.
 */
static bool valid_trustcache_module(const AppleModernBlob *tc, bool allow_v2,
                                    bool cryptex, Error **errp)
{
    uint32_t version, entries, entry_size;

    if (!tc->data || tc->size < 24 || tc->size > MAX_DT_SIZE) {
        return fail(errp, cryptex ?
                    "missing or malformed cryptex trustcache" :
                    "missing or malformed version-1 trustcache");
    }
    version = le32(tc->data);
    if (version == 1) {
        entry_size = 22;
    } else if (version == 2 && allow_v2) {
        entry_size = 24;
    } else if (version == 2) {
        return fail(errp, "version-2 trustcache needs trustcache-v2=on");
    } else if (allow_v2) {
        return fail(errp, "trustcache module version is neither 1 nor 2");
    } else {
        return fail(errp, cryptex ?
                    "missing or malformed cryptex trustcache" :
                    "missing or malformed version-1 trustcache");
    }
    /* uint32 count widened to uint64 before scaling, so no 32-bit wrap can
     * make a truncated or overlong module look exactly sized. */
    entries = le32(tc->data + 20);
    if (!entries ||
        (uint64_t)entries * entry_size + 24 != tc->size) {
        if (version == 1) {
            return fail(errp, cryptex ?
                        "missing or malformed cryptex trustcache" :
                        "missing or malformed version-1 trustcache");
        }
        return fail(errp, cryptex ?
                    "cryptex trustcache entry count does not match length" :
                    "version-2 trustcache entry count does not match length");
    }
    return true;
}

static bool region(AppleModernBootLayout *out, const char *name,
                   uint64_t address, uint64_t size, Error **errp)
{
    AppleModernBootRegion *r;
    if (out->region_count == APPLE_MODERN_MAX_REGIONS || !size ||
        address < out->dram_base || address % APPLE_MODERN_PAGE_SIZE ||
        size % APPLE_MODERN_PAGE_SIZE ||
        !span(address, size, out->dram_base + out->dram_size)) {
        return fail(errp, "boot region outside aligned DRAM");
    }
    for (size_t i = 0; i < out->region_count; i++) {
        r = &out->regions[i];
        if (address < r->physical_address + r->size &&
            r->physical_address < address + size) {
            return fail(errp, "boot regions overlap");
        }
    }
    r = &out->regions[out->region_count++];
    strcpy(r->name, name);
    r->physical_address = address;
    r->size = size;
    return true;
}

static bool group(AppleModernBootLayout *out, Image *image,
                  AppleModernImage source, const char *name,
                  const char *const *segments, size_t count,
                  uint64_t *cursor, Error **errp)
{
    uint64_t start = *cursor;
    for (size_t i = 0; i < count; i++) {
        if (!push_copy(out, image, source, segments[i], cursor, errp)) {
            return false;
        }
    }
    return region(out, name, start, *cursor - start, errp);
}

static bool build(const AppleModernBootInput *in, AppleModernBootLayout *out,
                  Error **errp)
{
    static const char *const txm_names[] = {"__TEXT", "__DATA_CONST", "__TEXT_EXEC", "__TEXT_BOOT_EXEC", "__DATA", "__LINKEDIT"};
    static const char *const bkc_names[] = {"__TEXT_EXEC", "__TEXT_BOOT_EXEC", "__TEXT", "__PRELINK_TEXT", "__DATA_CONST", "__DATA_SPTM", "__PRELINK_INFO", "__DATA", "__LINKEDIT"};
    static const char *const sptm_names[] = {"__TEXT", "__DATA_CONST", "__LATE_CONST", "__TEXT_EXEC", "__LAST", "__DATA", "__BOOTDATA", "__LINKEDIT"};
    Image images[3] = {0};
    DTree tree = { .blob = in->dtree };
    uint64_t tc_size, before, index, cursor, sptm_base, start;
    uint32_t tc_modules = 1;
    uint64_t framebuffer_size = 0;
    Image *bkc = &images[0], *sptm = &images[1], *txm = &images[2];
    /*
     * The copying path is capped at 4 GiB because the caller holds the whole
     * image in host anonymous memory. The declared opt-in mapped path hands
     * over a host file mapping instead, so only the DRAM reservation bounds
     * it (checked region by region below and against mem_size in metadata).
     */
    if ((!in->ramdisk.data != !in->ramdisk.size) ||
        in->ramdisk.size > (in->large_ramdisk ?
                            APPLE_MODERN_MAX_LARGE_RAMDISK_SIZE :
                            APPLE_MODERN_MAX_RAMDISK_SIZE)) {
        return fail(errp, "missing or oversized optional ramdisk bytes");
    }
    if (in->framebuffer_width || in->framebuffer_height ||
        in->framebuffer_stride) {
        uint64_t stride = in->framebuffer_stride ? in->framebuffer_stride :
                          (uint64_t)in->framebuffer_width * 4;
        if (!in->framebuffer_width || !in->framebuffer_height ||
            in->framebuffer_width > APPLE_MODERN_MAX_FRAMEBUFFER_DIMENSION ||
            in->framebuffer_height > APPLE_MODERN_MAX_FRAMEBUFFER_DIMENSION ||
            stride < (uint64_t)in->framebuffer_width * 4 || stride % 4) {
            return fail(errp, "invalid XRGB framebuffer geometry/stride");
        }
        /* Geometry bounds make this uint64_t product and rounding safe. */
        framebuffer_size = (stride * in->framebuffer_height +
                            APPLE_MODERN_FRAMEBUFFER_ALIGNMENT - 1) &
                           ~(APPLE_MODERN_FRAMEBUFFER_ALIGNMENT - 1);
        if (framebuffer_size > APPLE_MODERN_MAX_FRAMEBUFFER_SIZE) {
            return fail(errp, "framebuffer reservation exceeds 64 MiB");
        }
    }
    if (!in->dram_size || in->dram_base != (UINT64_C(1) << 40) ||
        in->dram_size > VIRTUAL_INDEX_MASK + 1 ||
        in->dram_size % APPLE_MODERN_PAGE_SIZE ||
        in->dram_size > UINT64_MAX - in->dram_base) {
        return fail(errp, "unsupported/unaligned/overflowing T8140 DRAM");
    }
    if (framebuffer_size &&
        in->dram_size % APPLE_MODERN_FRAMEBUFFER_ALIGNMENT) {
        return fail(errp, "framebuffer requires a 2 MiB-aligned DRAM tail");
    }
    if (!parse_image(in->bootkc, 12, bkc, errp) ||
        !parse_image(in->sptm, 2, sptm, errp) ||
        !parse_image(in->txm, 2, txm, errp)) {
        return false;
    }
    if (bkc->count != 9 || sptm->count != 8 || txm->count != 6) {
        return fail(errp, "unsupported modern image segment schema");
    }
    for (size_t i = 0; i < 9; i++) {
        if (!segment(bkc, bkc_names[i])) {
            return fail(errp, "missing required BootKC segment");
        }
    }
    for (size_t i = 0; i < 8; i++) {
        if (!segment(sptm, sptm_names[i])) {
            return fail(errp, "missing required SPTM segment");
        }
    }
    cursor = sptm->low;
    for (size_t i = 0; i < 8; i++) {
        Segment *s = segment(sptm, sptm_names[i]);
        if (s->va != cursor) {
            return fail(errp, "SPTM segments are not in required contiguous order");
        }
        cursor += s->size;
    }
    for (size_t i = 0; i < 6; i++) {
        if (!segment(txm, txm_names[i])) {
            return fail(errp, "missing required TXM segment");
        }
    }
    if (((sptm->low - txm->low) & VIRTUAL_INDEX_MASK) != SPTM_STRIDE ||
        ((sptm->low - bkc->low) & VIRTUAL_INDEX_MASK) != 2 * SPTM_STRIDE) {
        return fail(errp, "SPTM/TXM/BootKC virtual stride mismatch");
    }
    if (!in->dtree.data || in->dtree.size < 8 || in->dtree.size > MAX_DT_SIZE ||
        !parse_node(&tree, "", 0, errp)) {
        if (!errp || !*errp) {
            return fail(errp, "device tree missing/truncated/oversized");
        }
        return false;
    }
    if (tree.cursor != in->dtree.size || !tree.platform || !tree.cpu0) {
        return fail(errp, "device tree trailing data or missing T8140/CPU0");
    }
    /*
     * Trust-cache module geometry only; no entry is read, compared, merged or
     * rewritten here. The 24-byte module header is uint32 version, uuid[16],
     * uint32 numEntries, followed by numEntries packed entries. A version-1
     * entry is 22 bytes and a version-2 entry is 24 bytes; both start with the
     * 20-byte CDHash. Version 2 is accepted only when the caller opts in, so
     * the default board keeps refusing it exactly as before.
     */
    if (!valid_trustcache_module(&in->trustcache, in->trustcache_v2, false,
                                 errp)) {
        return false;
    }
    if (in->cryptex_trustcache.data || in->cryptex_trustcache.size) {
        if (!valid_trustcache_module(&in->cryptex_trustcache,
                                     in->trustcache_v2, true, errp)) {
            return false;
        }
        tc_modules = 2;
    }
    out->dram_base = in->dram_base;
    out->dram_size = in->dram_size;
    out->virtual_base = bkc->low & ~VIRTUAL_INDEX_MASK;
    out->dtree_node_count = tree.nodes;
    out->fileset_entry_count = bkc->filesets;
    strcpy(out->platform, "t8140");
    if (!round_page(in->dtree.size + APPLE_MODERN_DT_SLACK,
                    &out->dtree_capacity, errp) ||
        !round_page(in->trustcache.size + in->cryptex_trustcache.size +
                    4 + 4 * tc_modules, &tc_size, errp)) {
        return false;
    }
    before = out->dtree_capacity + APPLE_MODERN_PAGE_SIZE + tc_size;
    for (size_t i = 0; i < 4; i++) {
        uint64_t size = segment(txm, txm_names[i])->size;
        if (size > out->dram_size || before > out->dram_size - size) {
            return fail(errp, "TXM prefix exceeds DRAM");
        }
        before += size;
    }
    for (size_t i = 0; i < 6; i++) {
        uint64_t size = segment(bkc, bkc_names[i])->size;
        if (size > out->dram_size || before > out->dram_size - size) {
            return fail(errp, "BootKC prefix exceeds DRAM");
        }
        before += size;
    }
    index = bkc->low & VIRTUAL_INDEX_MASK;
    if (before > index || index > out->dram_size ||
        sptm->high - sptm->low > out->dram_size - index) {
        return fail(errp, "SPTM layout padding/DRAM is insufficient");
    }
    cursor = out->dram_base + index - before;
    if (!group(out, txm, APPLE_MODERN_TXM, "TXM-ro", txm_names, 2, &cursor, errp) ||
        !group(out, txm, APPLE_MODERN_TXM, "TXM-rx", txm_names + 2, 1, &cursor, errp) ||
        !group(out, txm, APPLE_MODERN_TXM, "TXM-bx", txm_names + 3, 1, &cursor, errp) ||
        !region(out, "TrustCache", cursor, tc_size, errp)) {
        return false;
    }
    /*
     * uint32 module count, then one uint32 byte offset per module. The first
     * module starts immediately after the header, which for a single module
     * reproduces the long-standing count = 1, offset = 8 catalog exactly.
     */
    out->trustcache_header_size = 4 + 4 * tc_modules;
    out->trustcache_module_count = tc_modules;
    out->trustcache_offsets_header[0] = (uint8_t)tc_modules;
    out->trustcache_offsets_header[4] = (uint8_t)out->trustcache_header_size;
    out->copies[out->copy_count++] = (AppleModernBootCopy){
        .image = APPLE_MODERN_TRUSTCACHE, .segment = "catalog",
        .file_size = in->trustcache.size,
        .physical_address = cursor + out->trustcache_header_size,
        .memory_size = in->trustcache.size,
    };
    if (tc_modules == 2) {
        uint32_t second = out->trustcache_header_size +
                          (uint32_t)in->trustcache.size;
        out->trustcache_offsets_header[8] = (uint8_t)(second & 0xff);
        out->trustcache_offsets_header[9] = (uint8_t)((second >> 8) & 0xff);
        out->trustcache_offsets_header[10] = (uint8_t)((second >> 16) & 0xff);
        out->trustcache_offsets_header[11] = (uint8_t)(second >> 24);
        out->copies[out->copy_count++] = (AppleModernBootCopy){
            .image = APPLE_MODERN_TRUSTCACHE, .segment = "catalog-cryptex",
            .file_size = in->cryptex_trustcache.size,
            .physical_address = cursor + second,
            .memory_size = in->cryptex_trustcache.size,
        };
    }
    cursor += tc_size;
    if (!group(out, bkc, APPLE_MODERN_BOOTKC, "BootKC-rx", bkc_names, 1, &cursor, errp) ||
        !group(out, bkc, APPLE_MODERN_BOOTKC, "BootKC-bx", bkc_names + 1, 1, &cursor, errp) ||
        !group(out, bkc, APPLE_MODERN_BOOTKC, "BootKC-ro", bkc_names + 2, 3, &cursor, errp) ||
        !group(out, bkc, APPLE_MODERN_BOOTKC, "BootKC-rs", bkc_names + 5, 1, &cursor, errp) ||
        !region(out, "DeviceTree", cursor, out->dtree_capacity + APPLE_MODERN_PAGE_SIZE, errp)) {
        return false;
    }
    out->dtree_physical = cursor + APPLE_MODERN_PAGE_SIZE;
    cursor += out->dtree_capacity + APPLE_MODERN_PAGE_SIZE;
    sptm_base = cursor;
    /* The validated name order equals the original SPTM virtual offsets. */
    if (!group(out, sptm, APPLE_MODERN_SPTM, "SPTM-ro", sptm_names, 3, &cursor, errp) ||
        !group(out, sptm, APPLE_MODERN_SPTM, "SPTM-rx", sptm_names + 3, 2, &cursor, errp) ||
        !group(out, sptm, APPLE_MODERN_SPTM, "SPTM-rw", sptm_names + 5, 2, &cursor, errp) ||
        !group(out, sptm, APPLE_MODERN_SPTM, "SPTM-le", sptm_names + 7, 1, &cursor, errp)) {
        return false;
    }
    if (cursor != sptm_base + sptm->high - sptm->low) {
        return fail(errp, "SPTM segments are not in required contiguous order");
    }
    if (!group(out, txm, APPLE_MODERN_TXM, "TXM-rw", txm_names + 4, 1, &cursor, errp) ||
        !group(out, txm, APPLE_MODERN_TXM, "TXM-le", txm_names + 5, 1, &cursor, errp) ||
        !group(out, bkc, APPLE_MODERN_BOOTKC, "BootKC-rw", bkc_names + 6, 2, &cursor, errp) ||
        !group(out, bkc, APPLE_MODERN_BOOTKC, "BootKC-le", bkc_names + 8, 1, &cursor, errp) ||
        !region(out, "CL4-dummypage", cursor, APPLE_MODERN_PAGE_SIZE, errp)) {
        return false;
    }
    cursor += APPLE_MODERN_PAGE_SIZE;
    out->bootargs_physical = cursor;
    start = cursor;
    if (!round_page(cursor + APPLE_MODERN_BOOTARGS_SIZE, &cursor, errp) ||
        !region(out, "BootArgs", start, cursor - start, errp)) {
        return false;
    }
    if (in->ramdisk.size) {
        uint64_t rounded;
        if (!round_page(in->ramdisk.size, &rounded, errp) ||
            !region(out, "RAMDisk", cursor, rounded, errp)) {
            return false;
        }
        out->ramdisk_physical = cursor;
        out->ramdisk_size = in->ramdisk.size;
        out->copies[out->copy_count++] = (AppleModernBootCopy){
            .image = APPLE_MODERN_RAMDISK, .segment = "ramdisk",
            .file_size = in->ramdisk.size, .physical_address = cursor,
            .memory_size = rounded,
        };
        cursor += rounded;
    }
    if (framebuffer_size) {
        uint64_t framebuffer_base;
        if (framebuffer_size > out->dram_size ||
            cursor - out->dram_base > out->dram_size - framebuffer_size) {
            return fail(errp, "framebuffer carveout overlaps boot data");
        }
        framebuffer_base = out->dram_base + out->dram_size - framebuffer_size;
        if (!region(out, "PurpleGfxMem", framebuffer_base,
                    framebuffer_size, errp)) {
            return false;
        }
        out->framebuffer_physical = framebuffer_base;
        out->framebuffer_size = framebuffer_size;
    }
    out->top_of_kernel_data = cursor;
    out->sptm_entry_physical = sptm_base + sptm->entry - sptm->low;
    for (size_t i = 0; i < 3; i++) {
        out->image_virtual_base[i] = images[i].low;
        out->image_entry_virtual[i] = images[i].entry;
    }
    return true;
}

bool apple_modern_boot_layout_build(const AppleModernBootInput *input,
                                   AppleModernBootLayout *output,
                                   Error **errp)
{
    AppleModernBootLayout temporary = {0};
    if (!output) {
        return fail(errp, "missing layout output");
    }
    if (input) {
        AppleModernBlob blobs[6] = {input->bootkc, input->sptm, input->txm,
                                    input->dtree, input->trustcache, input->ramdisk};
        uintptr_t begin = (uintptr_t)output;
        uintptr_t source = (uintptr_t)input;
        if (begin > UINTPTR_MAX - sizeof(*output) ||
            source > UINTPTR_MAX - sizeof(*input) ||
            (begin < source + sizeof(*input) &&
             source < begin + sizeof(*output))) {
            return fail(errp, "layout input/output struct alias");
        }
        for (size_t i = 0; i < 6; i++) {
            source = (uintptr_t)blobs[i].data;
            if (source > UINTPTR_MAX - blobs[i].size ||
                (blobs[i].size && begin < source + blobs[i].size &&
                 source < begin + sizeof(*output))) {
                return fail(errp, "layout input/output blob alias or pointer overflow");
            }
        }
    }
    memset(output, 0, sizeof(*output));
    if (!input) {
        return fail(errp, "missing layout input");
    }
    if (!build(input, &temporary, errp)) {
        return false;
    }
    *output = temporary;
    return true;
}
