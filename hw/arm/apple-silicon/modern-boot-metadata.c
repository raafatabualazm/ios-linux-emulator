/*
 * Bounded normal Apple boot metadata serialization. No guest writes.
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
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

#define MAX_ADT_BYTES ((UINT64_C(16) << 20) + APPLE_MODERN_DT_SLACK)
#define MAX_NORMAL_PROPS 48
_Static_assert(APPLE_MODERN_MAX_REGIONS + 15 <= MAX_NORMAL_PROPS,
               "normal metadata property budget");

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

typedef struct NormalProp {
    const char *name;
    uint8_t value[16];
} NormalProp;

typedef struct Tree {
    AppleModernBlob input;
    size_t cursor;
    uint32_t nodes;
    uint8_t *output;
    size_t used, capacity;
    NormalProp normal[MAX_NORMAL_PROPS];
    size_t normal_count;
    const AppleModernBootLayout *layout;
    unsigned chosen_count, map_count, vram_count;
    const char *probe_path, *probe_name;
    AppleModernBlob probe_value;
    unsigned probe_nodes, probe_properties;
} Tree;

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static void put32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) {
        p[i] = value >> (8 * i);
    }
}

static void put64(uint8_t *p, uint64_t value)
{
    put32(p, value);
    put32(p + 4, value >> 32);
}

static bool span(size_t start, size_t length, size_t limit)
{
    return start <= limit && length <= limit - start;
}

static bool fail(Error **errp, const char *reason)
{
    error_setg(errp, "modern boot metadata: %s", reason);
    return false;
}

static size_t bounded_length(const char *text, size_t limit)
{
    size_t length = 0;
    while (length < limit && text[length]) {
        length++;
    }
    return length;
}

static bool overlap(const void *a, size_t asize, const void *b, size_t bsize)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x > UINTPTR_MAX - asize || y > UINTPTR_MAX - bsize ||
           (asize && bsize && x < y + bsize && y < x + asize);
}

static bool emit(Tree *tree, const void *bytes, size_t length, Error **errp)
{
    if (!span(tree->used, length, tree->capacity)) {
        return fail(errp, "serialized ADT exceeds checked capacity");
    }
    if (length) {
        memcpy(tree->output + tree->used, bytes, length);
    }
    tree->used += length;
    return true;
}

static bool property(Tree *tree, const char *name, const void *bytes,
                     uint32_t size, Error **errp)
{
    uint8_t header[36] = {0}, zero[4] = {0};
    size_t length = strlen(name);
    if (!length || length >= 32) {
        return fail(errp, "generated ADT property name is invalid");
    }
    memcpy(header, name, length);
    put32(header + 32, size);
    return emit(tree, header, sizeof(header), errp) &&
           emit(tree, bytes, size, errp) &&
           emit(tree, zero, (4 - (size & 3)) & 3, errp);
}

static bool normal_property(const Tree *tree, const char *path,
                            const char *name)
{
    if (tree->layout && tree->layout->framebuffer_size &&
        !strcmp(path, "/vram")) {
        return !strcmp(name, "reg");
    }
    if (!strcmp(path, "/chosen")) {
        return !strcmp(name, "dram-base") || !strcmp(name, "dram-size");
    }
    if (!strcmp(path, "/chosen/memory-map")) {
        for (size_t i = 0; i < tree->normal_count; i++) {
            if (!strcmp(name, tree->normal[i].name)) {
                return true;
            }
        }
    }
    return false;
}

static bool emit_normal(Tree *tree, const char *path, Error **errp)
{
    if (tree->layout->framebuffer_size && !strcmp(path, "/vram")) {
        uint8_t bytes[16];
        put64(bytes, tree->layout->framebuffer_physical);
        put64(bytes + 8, tree->layout->framebuffer_size);
        return property(tree, "reg", bytes, sizeof(bytes), errp);
    }
    if (!strcmp(path, "/chosen")) {
        uint8_t bytes[8];
        put64(bytes, tree->layout->dram_base);
        if (!property(tree, "dram-base", bytes, sizeof(bytes), errp)) {
            return false;
        }
        put64(bytes, tree->layout->dram_size);
        return property(tree, "dram-size", bytes, sizeof(bytes), errp);
    }
    if (!strcmp(path, "/chosen/memory-map")) {
        for (size_t i = 0; i < tree->normal_count; i++) {
            if (!property(tree, tree->normal[i].name, tree->normal[i].value,
                          16, errp)) {
                return false;
            }
        }
    }
    return true;
}

/* Validate each bounded node; unchanged property headers/padding stay exact. */
static bool walk(Tree *tree, const char *parent, unsigned depth, Error **errp)
{
    const uint8_t *names[4096];
    uint32_t count, children, replaced = 0;
    size_t start, end, output_header = tree->used;
    char name[128] = "", path[512];
    bool chosen, map, vram;
    if (depth > 32 || ++tree->nodes > 8192 ||
        !span(tree->cursor, 8, tree->input.size)) {
        return fail(errp, "ADT node depth/count/bounds exceeded");
    }
    count = get32(tree->input.data + tree->cursor);
    children = get32(tree->input.data + tree->cursor + 4);
    tree->cursor += 8;
    if (!count || count > 4096 || children > 8192) {
        return fail(errp, "invalid ADT node counts");
    }
    start = tree->cursor;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p, *nul;
        uint32_t length;
        size_t rounded;
        if (!span(tree->cursor, 36, tree->input.size)) {
            return fail(errp, "truncated ADT property header");
        }
        p = tree->input.data + tree->cursor;
        if (!p[0] || !memchr(p, 0, 32)) {
            return fail(errp, "invalid ADT property name");
        }
        for (uint32_t j = 0; j < i; j++) {
            if (!strcmp((const char *)names[j], (const char *)p)) {
                return fail(errp, "duplicate ADT property");
            }
        }
        names[i] = p;
        length = get32(p + 32) & 0x7fffffff;
        rounded = ((size_t)length + 3) & ~(size_t)3;
        tree->cursor += 36;
        if (!span(tree->cursor, rounded, tree->input.size)) {
            return fail(errp, "ADT property exceeds input");
        }
        if (!strcmp((const char *)p, "name")) {
            nul = memchr(tree->input.data + tree->cursor, 0, length);
            if (!nul || nul == tree->input.data + tree->cursor ||
                (size_t)(nul - tree->input.data - tree->cursor) >= sizeof(name)) {
                return fail(errp, "invalid ADT node name");
            }
            memcpy(name, tree->input.data + tree->cursor,
                   nul - tree->input.data - tree->cursor);
        }
        tree->cursor += rounded;
    }
    end = tree->cursor;
    if (!name[0] || (depth && (strchr(name, '/') || !strcmp(name, ".") ||
                              !strcmp(name, ".."))) ||
        snprintf(path, sizeof(path), "%s%s%s", parent,
                 depth ? "/" : "", depth ? name : "") >= (int)sizeof(path)) {
        return fail(errp, "invalid or excessive ADT path");
    }
    chosen = !strcmp(path, "/chosen");
    map = !strcmp(path, "/chosen/memory-map");
    vram = tree->layout && tree->layout->framebuffer_size &&
           !strcmp(path, "/vram");
    if ((chosen && ++tree->chosen_count > 1) ||
        (map && ++tree->map_count > 1) ||
        (vram && ++tree->vram_count > 1)) {
        return fail(errp, "ambiguous ADT chosen/memory-map/vram path");
    }
    if (tree->probe_path && !strcmp(path, tree->probe_path)) {
        tree->probe_nodes++;
    }
    if (tree->output) {
        uint8_t header[8];
        put32(header, count);
        put32(header + 4, children);
        if (!emit(tree, header, sizeof(header), errp)) {
            return false;
        }
    }
    for (size_t cursor = start; cursor < end;) {
        const uint8_t *p = tree->input.data + cursor;
        uint32_t length = get32(p + 32) & 0x7fffffff;
        size_t size = 36 + (((size_t)length + 3) & ~(size_t)3);
        if (tree->probe_path && !strcmp(path, tree->probe_path) &&
            !strcmp((const char *)p, tree->probe_name)) {
            tree->probe_properties++;
            tree->probe_value = (AppleModernBlob){p + 36, length};
        }
        if (tree->output) {
            if (normal_property(tree, path, (const char *)p)) {
                replaced++;
            } else if (!emit(tree, p, size, errp)) {
                return false;
            }
        }
        cursor += size;
    }
    if (tree->output) {
        size_t added = chosen ? 2 : map ? tree->normal_count : vram ? 1 : 0;
        if (count - replaced + added > 4096) {
            return fail(errp, "generated ADT node property count exceeds bound");
        }
        if (!emit_normal(tree, path, errp)) {
            return false;
        }
        put32(tree->output + output_header, count - replaced + added);
    }
    for (uint32_t i = 0; i < children; i++) {
        if (!walk(tree, path, depth + 1, errp)) {
            return false;
        }
    }
    if (tree->output && chosen && !tree->map_count) {
        uint8_t header[8];
        if (children == 8192 || ++tree->nodes > 8192) {
            return fail(errp, "cannot append ADT memory-map child");
        }
        put32(header, tree->normal_count + 1);
        put32(header + 4, 0);
        if (!emit(tree, header, sizeof(header), errp) ||
            !property(tree, "name", "memory-map", 11, errp) ||
            !emit_normal(tree, "/chosen/memory-map", errp)) {
            return false;
        }
        put32(tree->output + output_header + 4, children + 1);
        tree->map_count = 1;
    }
    return true;
}

static bool valid_blob(AppleModernBlob blob, Error **errp)
{
    if (!blob.data || blob.size < 8 || blob.size > MAX_ADT_BYTES ||
        (uintptr_t)blob.data > UINTPTR_MAX - blob.size) {
        return fail(errp, "missing, overflowing or oversized ADT blob");
    }
    return true;
}

bool apple_modern_adt_property(AppleModernBlob dtree, const char *path,
                              const char *name, AppleModernBlob *value,
                              Error **errp)
{
    Tree tree = {.input = dtree};
    size_t path_length, name_length;
    if (!value) {
        return fail(errp, "missing ADT property output");
    }
    if (overlap(value, sizeof(*value), dtree.data, dtree.size)) {
        return fail(errp, "ADT property output aliases input");
    }
    path_length = path ? bounded_length(path, 512) : 0;
    name_length = name ? bounded_length(name, 32) : 0;
    if ((path && overlap(value, sizeof(*value), path,
                         path_length < 512 ? path_length + 1 : 512)) ||
        (name && overlap(value, sizeof(*value), name,
                         name_length < 32 ? name_length + 1 : 32))) {
        return fail(errp, "ADT property output aliases path/name");
    }
    *value = (AppleModernBlob){0};
    if (!valid_blob(dtree, errp) || !path || !name) {
        if (!errp || !*errp) {
            return fail(errp, "missing ADT property path/name");
        }
        return false;
    }
    if (path_length == 512 || !name_length || name_length == 32 ||
        path[0] != '/' ||
        (path_length > 1 && path[path_length - 1] == '/')) {
        return fail(errp, "invalid ADT property path/name");
    }
    tree.probe_path = !strcmp(path, "/") ? "" : path;
    tree.probe_name = name;
    if (!walk(&tree, "", 0, errp)) {
        return false;
    }
    if (tree.cursor != dtree.size || tree.probe_nodes != 1 ||
        tree.probe_properties != 1) {
        return fail(errp, "ADT property missing/ambiguous or trailing bytes");
    }
    *value = tree.probe_value;
    return true;
}

static void add_normal(Tree *tree, const char *name, uint64_t address,
                       uint64_t size)
{
    NormalProp *p = &tree->normal[tree->normal_count++];
    p->name = name;
    put64(p->value, address);
    put64(p->value + 8, size);
}

static void prepare_normal(Tree *tree, const AppleModernBootLayout *layout)
{
    static const char *const virt[] = {"BootKC-virt", "SPTM-virt", "TXM-virt"};
    static const char *const entry[] = {"BootKC-entry", "SPTM-entry", "TXM-entry"};
    static const char *const unused[] = {"SPTM-rm", "CL4-rx", "CL4-ro",
                                        "CL4-rw", "CL4-le", "CL4-entry", "CL4-virt"};
    tree->layout = layout;
    for (size_t i = 0; i < layout->region_count; i++) {
        const AppleModernBootRegion *r = &layout->regions[i];
        add_normal(tree, r->name, r->physical_address, r->size);
    }
    for (size_t i = 0; i < 3; i++) {
        add_normal(tree, virt[i], layout->image_virtual_base[i], 0);
        add_normal(tree, entry[i], layout->image_entry_virtual[i], 0);
    }
    add_normal(tree, "slide", 0, 0);
    for (size_t i = 0; i < sizeof(unused) / sizeof(unused[0]); i++) {
        add_normal(tree, unused[i], UINT64_MAX, UINT64_MAX);
    }
    if (!layout->ramdisk_size) {
        add_normal(tree, "RAMDisk", UINT64_MAX, UINT64_MAX);
    }
}

void apple_modern_boot_metadata_clear(AppleModernBootMetadata *output)
{
    if (output) {
        free(output->dtree);
        free(output->trustcache);
        memset(output, 0, sizeof(*output));
    }
}

bool apple_modern_boot_metadata_build(const AppleModernBootMetadataInput *input,
                                     AppleModernBootMetadata *output,
                                     Error **errp)
{
    AppleModernBootMetadata prepared = {0};
    Tree tree = {0};
    size_t capacity;
    const AppleModernBootInput *components;
    uint64_t mem_size, dtree_virtual;
    AppleModernBootVideo video;
    if (!output) {
        return fail(errp, "missing metadata output");
    }
    if (input && overlap(output, sizeof(*output), input, sizeof(*input))) {
        return fail(errp, "metadata input/output struct alias");
    }
    if (input && overlap(output, sizeof(*output), input->command_line,
                         input->command_line_length)) {
        return fail(errp, "metadata output aliases command line");
    }
    if (input && input->components) {
        components = input->components;
        if (overlap(output, sizeof(*output), components, sizeof(*components))) {
            return fail(errp, "metadata output aliases component struct");
        }
        AppleModernBlob blobs[6] = {components->bootkc, components->sptm,
                                    components->txm, components->dtree,
                                    components->trustcache, components->ramdisk};
        for (size_t i = 0; i < 6; i++) {
            if (overlap(output, sizeof(*output), blobs[i].data, blobs[i].size)) {
                return fail(errp, "metadata output aliases component blob");
            }
        }
    }
    memset(output, 0, sizeof(*output));
    if (!input || !input->components) {
        return fail(errp, "missing metadata components");
    }
    components = input->components;
    if (input->command_line_length >= APPLE_MODERN_COMMAND_LINE_SIZE ||
        (!input->command_line && input->command_line_length) ||
        (input->command_line_length &&
         memchr(input->command_line, 0, input->command_line_length))) {
        return fail(errp, "command line missing, contains NUL or exceeds ABI");
    }
    if (!apple_modern_boot_layout_build(components, &prepared.layout, errp)) {
        return false;
    }
    mem_size = input->has_mte ? prepared.layout.dram_size / 32 * 31 :
                               prepared.layout.dram_size;
    if (prepared.layout.framebuffer_size) {
        /*
         * Normal iBoot framebuffer handoff: reserve the final managed DRAM
         * tail and reduce memSize, without adding untyped bootstrap pages
         * below topOfKernelData. Reference: d0lb33/qemu-sptm b0f7bc6,
         * hw/arm/xnuboot_sptm.c setup_framebuffer().
         */
        uint64_t framebuffer_size = prepared.layout.framebuffer_size;
        if (mem_size % APPLE_MODERN_FRAMEBUFFER_ALIGNMENT ||
            framebuffer_size >= mem_size ||
            prepared.layout.top_of_kernel_data - prepared.layout.dram_base >
            mem_size - framebuffer_size) {
            return fail(errp, "framebuffer overlaps boot data or unaligned usable DRAM");
        }
        mem_size -= framebuffer_size;
        prepared.layout.framebuffer_physical = prepared.layout.dram_base +
                                               mem_size;
        for (size_t i = 0; i < prepared.layout.region_count; i++) {
            AppleModernBootRegion *r = &prepared.layout.regions[i];
            if (!strcmp(r->name, "PurpleGfxMem")) {
                r->physical_address = prepared.layout.framebuffer_physical;
            }
        }
    }
    video = input->video;
    if (prepared.layout.framebuffer_size) {
        AppleModernBootVideo derived = {
            .base_address = prepared.layout.framebuffer_physical,
            /* XNU PE_create_console selects its text console when zero. */
            .display = 0,
            .row_bytes = components->framebuffer_stride ?
                         components->framebuffer_stride :
                         (uint64_t)components->framebuffer_width * 4,
            .width = components->framebuffer_width,
            .height = components->framebuffer_height,
            .depth = 32,
        };
        if ((video.base_address || video.display || video.row_bytes ||
             video.width || video.height || video.depth) &&
            (video.base_address != derived.base_address ||
             video.display != derived.display ||
             video.row_bytes != derived.row_bytes ||
             video.width != derived.width || video.height != derived.height ||
             video.depth != derived.depth)) {
            return fail(errp, "explicit Video conflicts with reserved framebuffer");
        }
        video = derived;
    }
    capacity = input->dtree_capacity_limit ? input->dtree_capacity_limit :
               prepared.layout.dtree_capacity;
    if (!capacity || capacity > prepared.layout.dtree_capacity ||
        capacity > MAX_ADT_BYTES) {
        return fail(errp, "ADT capacity exceeds computed reservation");
    }
    prepared.dtree = calloc(1, capacity);
    if (!prepared.dtree) {
        return fail(errp, "cannot allocate bounded ADT output");
    }
    tree.input = components->dtree;
    tree.output = prepared.dtree;
    tree.capacity = capacity;
    prepare_normal(&tree, &prepared.layout);
    if (!walk(&tree, "", 0, errp) || tree.cursor != components->dtree.size ||
        tree.chosen_count != 1 || tree.map_count != 1) {
        if (!errp || !*errp) {
            fail(errp, "ADT chosen path missing or serialization incomplete");
        }
        goto failed;
    }
    prepared.dtree_size = tree.used;
    prepared.layout.dtree_node_count = tree.nodes;
    prepared.trustcache_size = components->trustcache.size + 8;
    prepared.trustcache = malloc(prepared.trustcache_size);
    if (!prepared.trustcache) {
        fail(errp, "cannot allocate bounded stock trustcache output");
        goto failed;
    }
    memcpy(prepared.trustcache, prepared.layout.trustcache_offsets_header, 8);
    memcpy(prepared.trustcache + 8, components->trustcache.data,
           components->trustcache.size);
    dtree_virtual = prepared.layout.virtual_base +
                    prepared.layout.dtree_physical - prepared.layout.dram_base;
    if (prepared.layout.top_of_kernel_data - prepared.layout.dram_base >
        mem_size) {
        fail(errp, "metadata/ramdisk/framebuffer exceeds usable DRAM");
        goto failed;
    }
    /* ARM64 boot_args ABI: explicit LE offsets, independent of host packing. */
    put16(prepared.bootargs, 2);
    put16(prepared.bootargs + 2, 2);
    put64(prepared.bootargs + 8, prepared.layout.virtual_base);
    put64(prepared.bootargs + 16, prepared.layout.dram_base);
    put64(prepared.bootargs + 24, mem_size);
    put64(prepared.bootargs + 32, prepared.layout.top_of_kernel_data);
    put64(prepared.bootargs + 40, video.base_address);
    put64(prepared.bootargs + 48, video.display);
    put64(prepared.bootargs + 56, video.row_bytes);
    put64(prepared.bootargs + 64, video.width);
    put64(prepared.bootargs + 72, video.height);
    put64(prepared.bootargs + 80, video.depth);
    put64(prepared.bootargs + 96, dtree_virtual);
    put32(prepared.bootargs + 104, prepared.dtree_size);
    if (input->command_line_length) {
        memcpy(prepared.bootargs + 108, input->command_line,
               input->command_line_length);
    }
    put64(prepared.bootargs + 1136, input->boot_flags);
    put64(prepared.bootargs + 1144, prepared.layout.dram_size);
    *output = prepared;
    return true;

failed:
    apple_modern_boot_metadata_clear(&prepared);
    return false;
}
