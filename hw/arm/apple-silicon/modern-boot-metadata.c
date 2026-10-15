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
    unsigned chosen_count, map_count, vram_count, aic_count;
    uint32_t aic_iack_offset;
    bool chosen_sepfw_absent;
    /*
     * dart-id generation. dart_pending and dart_value describe only the node
     * whose properties are being emitted: walk() sets them after reading the
     * node's properties and clears them once emit_normal() has run, before any
     * child is walked.
     */
    bool assign_dart_ids, dart_pending;
    uint32_t dart_value, dart_count;
    const AppleModernAdtOverride *overrides;
    size_t override_count;
    unsigned override_hits[APPLE_MODERN_MAX_ADT_OVERRIDES];
    const char *probe_path, *probe_name;
    AppleModernBlob probe_value;
    unsigned probe_nodes, probe_properties;
} Tree;

#define ARRAY_SIZE_LOCAL(a) (sizeof(a) / sizeof((a)[0]))

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

static size_t override_nodes_at(const Tree *tree, const char *path)
{
    size_t n = 0;
    for (size_t i = 0; i < tree->override_count; i++) {
        n += !strcmp(path, tree->overrides[i].path);
    }
    return n;
}

/* True when the NUL-separated "compatible" list has an entry equal to wanted. */
static bool compatible_has(const uint8_t *list, uint32_t length,
                           const char *wanted)
{
    size_t wanted_length = strlen(wanted);
    size_t start = 0;

    while (start < length) {
        const uint8_t *end = memchr(list + start, 0, length - start);
        size_t entry = end ? (size_t)(end - (list + start)) : length - start;

        if (entry == wanted_length && !memcmp(list + start, wanted, entry)) {
            return true;
        }
        start += entry + 1;
    }
    return false;
}

static bool normal_property(const Tree *tree, const char *path,
                            const char *name)
{
    if (tree->dart_pending && !strcmp(name, "dart-id")) {
        return true;
    }
    for (size_t i = 0; i < tree->override_count; i++) {
        if (!strcmp(path, tree->overrides[i].path) &&
            !strcmp(name, tree->overrides[i].name)) {
            return true;
        }
    }
    if (tree->layout && tree->layout->framebuffer_size &&
        !strcmp(path, "/vram")) {
        return !strcmp(name, "reg");
    }
    if (!strcmp(path, "/chosen")) {
        return !strcmp(name, "dram-base") || !strcmp(name, "dram-size") ||
               (tree->chosen_sepfw_absent &&
                !strcmp(name, "sepfw-load-at-boot"));
    }
    if (!strcmp(path, "/chosen/memory-map")) {
        for (size_t i = 0; i < tree->normal_count; i++) {
            if (!strcmp(name, tree->normal[i].name)) {
                return true;
            }
        }
    }
    if (tree->aic_iack_offset && !strcmp(path, "/arm-io/aic")) {
        return !strcmp(name, "aic-iack-offset");
    }
    return false;
}

static bool emit_normal(Tree *tree, const char *path, Error **errp)
{
    if (tree->dart_pending) {
        uint8_t bytes[4];

        put32(bytes, tree->dart_value);
        if (!property(tree, "dart-id", bytes, sizeof(bytes), errp)) {
            return false;
        }
    }
    /* Overrides never target the loader-owned nodes handled below. */
    for (size_t i = 0; i < tree->override_count; i++) {
        const AppleModernAdtOverride *o = &tree->overrides[i];
        if (!strcmp(path, o->path) &&
            !property(tree, o->name, o->value, o->size, errp)) {
            return false;
        }
    }
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
        if (!property(tree, "dram-size", bytes, sizeof(bytes), errp)) {
            return false;
        }
        if (tree->chosen_sepfw_absent) {
            put32(bytes, 0);
            return property(tree, "sepfw-load-at-boot", bytes, 4, errp);
        }
        return true;
    }
    if (!strcmp(path, "/chosen/memory-map")) {
        for (size_t i = 0; i < tree->normal_count; i++) {
            if (!property(tree, tree->normal[i].name, tree->normal[i].value,
                          16, errp)) {
                return false;
            }
        }
    }
    if (tree->aic_iack_offset && !strcmp(path, "/arm-io/aic")) {
        uint8_t bytes[8];
        /*
         * XNU rejects any length other than eight: the reader compares the
         * property length against 8 and panics at
         * AppleInterruptControllerV3.cpp:195 otherwise.
         */
        put64(bytes, tree->aic_iack_offset);
        return property(tree, "aic-iack-offset", bytes, sizeof(bytes), errp);
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
    bool chosen, map, vram, aic, dart = false;
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
        if (tree->assign_dart_ids && !strcmp((const char *)p, "compatible")) {
            dart = compatible_has(tree->input.data + tree->cursor, length,
                                  "dart,t8110");
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
    aic = tree->aic_iack_offset && !strcmp(path, "/arm-io/aic");
    if ((chosen && ++tree->chosen_count > 1) ||
        (map && ++tree->map_count > 1) ||
        (vram && ++tree->vram_count > 1) ||
        (aic && ++tree->aic_count > 1)) {
        return fail(errp, "ambiguous ADT chosen/memory-map/vram/aic path");
    }
    if (tree->probe_path && !strcmp(path, tree->probe_path)) {
        tree->probe_nodes++;
    }
    for (size_t i = 0; i < tree->override_count; i++) {
        if (!strcmp(path, tree->overrides[i].path) &&
            ++tree->override_hits[i] > 1) {
            return fail(errp, "ambiguous ADT override path");
        }
    }
    if (dart) {
        /* Generation order is the depth-first order of the input blob. */
        tree->dart_pending = true;
        tree->dart_value = tree->dart_count++;
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
        size_t added = chosen ? 2u + tree->chosen_sepfw_absent :
                       map ? tree->normal_count : vram ? 1 : aic ? 1 : 0;
        added += override_nodes_at(tree, path);
        added += tree->dart_pending;
        if (count - replaced + added > 4096) {
            return fail(errp, "generated ADT node property count exceeds bound");
        }
        if (!emit_normal(tree, path, errp)) {
            return false;
        }
        put32(tree->output + output_header, count - replaced + added);
    }
    tree->dart_pending = false;
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

/* Alias checks only; they must run before the output is touched. */
static bool overrides_alias_output(const AppleModernBootMetadataInput *input,
                                   const AppleModernBootMetadata *output)
{
    size_t n = input->override_count;
    if (!n || !input->overrides) {
        return false;
    }
    if (n > APPLE_MODERN_MAX_ADT_OVERRIDES) {
        n = APPLE_MODERN_MAX_ADT_OVERRIDES;
    }
    if (overlap(output, sizeof(*output), input->overrides,
                n * sizeof(*input->overrides))) {
        return true;
    }
    for (size_t i = 0; i < n; i++) {
        const AppleModernAdtOverride *o = &input->overrides[i];
        if ((o->path && overlap(output, sizeof(*output), o->path,
                                bounded_length(o->path, 256) + 1)) ||
            (o->name && overlap(output, sizeof(*output), o->name,
                                bounded_length(o->name, 32) + 1)) ||
            (o->value && overlap(output, sizeof(*output), o->value, o->size))) {
            return true;
        }
    }
    return false;
}

static bool valid_overrides(const AppleModernBootMetadataInput *input,
                            Error **errp)
{
    static const char *const owned[] = {"/chosen", "/chosen/memory-map",
                                        "/vram", "/arm-io/aic"};
    if (!input->override_count) {
        return true;
    }
    if (!input->overrides || input->override_count > APPLE_MODERN_MAX_ADT_OVERRIDES) {
        return fail(errp, "ADT override list missing or too long");
    }
    for (size_t i = 0; i < input->override_count; i++) {
        const AppleModernAdtOverride *o = &input->overrides[i];
        size_t path_length, name_length;
        if (!o->path || !o->name || (o->size && !o->value)) {
            return fail(errp, "ADT override has a missing path, name or value");
        }
        path_length = bounded_length(o->path, 256);
        name_length = bounded_length(o->name, 32);
        if (path_length == 256 || path_length < 2 || o->path[0] != '/' ||
            o->path[path_length - 1] == '/' || !name_length ||
            name_length == 32 || !strcmp(o->name, "name") ||
            !o->size || o->size > APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES) {
            return fail(errp, "ADT override path, name or size is invalid");
        }
        for (size_t j = 0; j < ARRAY_SIZE_LOCAL(owned); j++) {
            if (!strcmp(o->path, owned[j])) {
                return fail(errp, "ADT override targets a loader-owned node");
            }
        }
        if (input->assign_dart_ids && !strcmp(o->name, "dart-id")) {
            return fail(errp, "ADT override conflicts with generated dart-id");
        }
        for (size_t j = 0; j < i; j++) {
            if (!strcmp(o->path, input->overrides[j].path) &&
                !strcmp(o->name, input->overrides[j].name)) {
                return fail(errp, "duplicate ADT override");
            }
        }
    }
    return true;
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
        AppleModernBlob blobs[7] = {components->bootkc, components->sptm,
                                    components->txm, components->dtree,
                                    components->trustcache, components->ramdisk,
                                    components->cryptex_trustcache};
        for (size_t i = 0; i < 7; i++) {
            if (overlap(output, sizeof(*output), blobs[i].data, blobs[i].size)) {
                return fail(errp, "metadata output aliases component blob");
            }
        }
    }
    if (input && overrides_alias_output(input, output)) {
        return fail(errp, "metadata output aliases ADT override data");
    }
    memset(output, 0, sizeof(*output));
    if (!input || !input->components) {
        return fail(errp, "missing metadata components");
    }
    components = input->components;
    if (!valid_overrides(input, errp)) {
        return false;
    }
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
    tree.aic_iack_offset = input->aic_iack_offset;
    tree.chosen_sepfw_absent = input->chosen_sepfw_absent;
    tree.assign_dart_ids = input->assign_dart_ids;
    tree.overrides = input->overrides;
    tree.override_count = input->override_count;
    prepare_normal(&tree, &prepared.layout);
    if (!walk(&tree, "", 0, errp) || tree.cursor != components->dtree.size ||
        tree.chosen_count != 1 || tree.map_count != 1 ||
        (tree.aic_iack_offset && tree.aic_count != 1)) {
        if (!errp || !*errp) {
            fail(errp, "ADT chosen path missing or serialization incomplete");
        }
        goto failed;
    }
    for (size_t i = 0; i < tree.override_count; i++) {
        if (tree.override_hits[i] != 1) {
            fail(errp, "ADT override node does not exist");
            goto failed;
        }
    }
    if (tree.assign_dart_ids && !tree.dart_count) {
        fail(errp, "dart-id assignment requested but the ADT has no "
                   "dart,t8110 node (Darwin-derived trees strip every DART "
                   "compatible)");
        goto failed;
    }
    prepared.dart_id_count = tree.dart_count;
    prepared.dtree_size = tree.used;
    prepared.layout.dtree_node_count = tree.nodes;
    /*
     * The catalog the loader publishes: the offsets header the layout built,
     * then each module's own bytes unchanged. The layout has already checked
     * every module's geometry and set the header, so the sizes here agree with
     * the offsets in it by construction.
     */
    prepared.trustcache_size = prepared.layout.trustcache_header_size +
                               components->trustcache.size +
                               components->cryptex_trustcache.size;
    prepared.trustcache = malloc(prepared.trustcache_size);
    if (!prepared.trustcache) {
        fail(errp, "cannot allocate bounded stock trustcache output");
        goto failed;
    }
    memcpy(prepared.trustcache, prepared.layout.trustcache_offsets_header,
           prepared.layout.trustcache_header_size);
    memcpy(prepared.trustcache + prepared.layout.trustcache_header_size,
           components->trustcache.data, components->trustcache.size);
    if (prepared.layout.trustcache_module_count == 2) {
        memcpy(prepared.trustcache + prepared.layout.trustcache_header_size +
               components->trustcache.size,
               components->cryptex_trustcache.data,
               components->cryptex_trustcache.size);
    }
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
