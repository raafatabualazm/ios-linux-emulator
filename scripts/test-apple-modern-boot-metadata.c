/* Production-source tests, no guest launch.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *   -fsanitize=address,undefined -fno-omit-frame-pointer \
 *   hw/arm/apple-silicon/modern-boot-layout.c \
 *   hw/arm/apple-silicon/modern-boot-metadata.c \
 *   scripts/test-apple-modern-boot-metadata.c -o /tmp/test-modern-metadata
 */
#define main layout_regression_main
#include "test-apple-modern-boot-layout.c"
#undef main
#include <stddef.h>
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/* Independent ordinary ARM64 ABI structure, including compiler padding. */
typedef struct ReferenceArgs {
    uint16_t revision, version;
    uint64_t virt, phys, memory, top;
    uint64_t video[6];
    uint32_t machine;
    uint64_t dtree;
    uint32_t dtree_length;
    char command[1024];
    uint64_t flags, memory_actual;
} ReferenceArgs;

_Static_assert(sizeof(ReferenceArgs) == 1152, "ARM64 boot_args ABI size");
_Static_assert(offsetof(ReferenceArgs, command) == 108, "command ABI offset");
_Static_assert(offsetof(ReferenceArgs, flags) == 1136, "flags ABI offset");
_Static_assert(offsetof(ReferenceArgs, video) == 40, "Boot_Video ABI offset");

static uint64_t get64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) {
        value |= (uint64_t)p[i] << (8 * i);
    }
    return value;
}

static size_t fixture_chosen_start;

static AppleModernBootInput metadata_fixture(void)
{
    AppleModernBootInput in = fixture();
    uint8_t *dt = calloc(1, 8192);
    size_t p = 8;
    assert(dt);
    free((void *)in.dtree.data);
    put32(dt, 2); put32(dt + 4, 3);
    prop(dt, &p, "name", "/"); prop(dt, &p, "unchanged-root", "root bytes");
    put32(dt + p, 2); put32(dt + p + 4, 1); p += 8;
    prop(dt, &p, "name", "arm-io"); prop(dt, &p, "compatible", "arm-io,t8140");
    put32(dt + p, 2); p += 8;
    prop(dt, &p, "name", "sgx"); prop(dt, &p, "compatible", "original graphics");
    put32(dt + p, 1); put32(dt + p + 4, 1); p += 8; prop(dt, &p, "name", "cpus");
    put32(dt + p, 2); p += 8;
    prop(dt, &p, "name", "cpu0"); prop(dt, &p, "state", "original state");
    fixture_chosen_start = p;
    put32(dt + p, 3); put32(dt + p + 4, 1); p += 8;
    prop(dt, &p, "name", "chosen");
    prop(dt, &p, "dram-base", "replace this ordinary metadata");
    prop(dt, &p, "secure-boot", "unchanged policy");
    put32(dt + p, 3); p += 8;
    prop(dt, &p, "name", "memory-map");
    prop(dt, &p, "MemoryMapReserved-0", "unchanged firmware mapping");
    prop(dt, &p, "BootArgs", "replace this ordinary mapping");
    in.dtree = (AppleModernBlob){dt, p};
    return in;
}

static void free_components(AppleModernBootInput *in)
{
    free((void *)in->bootkc.data); free((void *)in->sptm.data);
    free((void *)in->txm.data); free((void *)in->dtree.data);
    free((void *)in->trustcache.data);
}

static void rejected_metadata(const char *label,
                              const AppleModernBootMetadataInput *input)
{
    AppleModernBootMetadata output, zero = {0};
    Error *error = NULL;
    memset(&output, 0x5a, sizeof(output));
    assert(!apple_modern_boot_metadata_build(input, &output, &error));
    if (!error || memcmp(&output, &zero, sizeof(output))) {
        fprintf(stderr, "unclean failure %s: %s\n", label,
                error ? error->message : "missing error");
    }
    assert(error && !memcmp(&output, &zero, sizeof(output)));
    printf("REJECT %s: %s\n", label, error->message);
    error_free(error);
    checks++;
}

static AppleModernBlob prop_view(const AppleModernBootMetadata *output,
                                 const char *path, const char *name)
{
    AppleModernBlob view;
    Error *error = NULL;
    assert(apple_modern_adt_property((AppleModernBlob){output->dtree,
                                    output->dtree_size}, path, name,
                                    &view, &error));
    assert(!error);
    return view;
}

static void verify_metadata(const AppleModernBootMetadataInput *input,
                            const AppleModernBootMetadata *output)
{
    ReferenceArgs args = {0};
    AppleModernBlob view;
    const AppleModernBootLayout *layout = &output->layout;
    args.revision = args.version = 2;
    args.virt = layout->virtual_base; args.phys = layout->dram_base;
    args.memory = input->has_mte ? layout->dram_size / 32 * 31 : layout->dram_size;
    args.memory -= layout->framebuffer_size;
    args.top = layout->top_of_kernel_data;
    args.video[0] = input->video.base_address; args.video[1] = input->video.display;
    args.video[2] = input->video.row_bytes; args.video[3] = input->video.width;
    args.video[4] = input->video.height; args.video[5] = input->video.depth;
    if (input->components->framebuffer_width) {
        args.video[0] = layout->framebuffer_physical;
        args.video[1] = 0;
        args.video[2] = input->components->framebuffer_stride ?
                        input->components->framebuffer_stride :
                        (uint64_t)input->components->framebuffer_width * 4;
        args.video[3] = input->components->framebuffer_width;
        args.video[4] = input->components->framebuffer_height;
        args.video[5] = 32;
    }
    args.dtree = layout->virtual_base + layout->dtree_physical - layout->dram_base;
    args.dtree_length = output->dtree_size;
    if (input->command_line_length) {
        memcpy(args.command, input->command_line, input->command_line_length);
    }
    args.flags = input->boot_flags; args.memory_actual = layout->dram_size;
    assert(!memcmp(output->bootargs, &args, sizeof(args)));
    assert(output->dtree_size <= layout->dtree_capacity);
    assert(output->trustcache_size == input->components->trustcache.size + 8);
    assert(get64(output->trustcache) == UINT64_C(0x800000001));
    assert(!memcmp(output->trustcache + 8, input->components->trustcache.data,
                   input->components->trustcache.size));
    for (size_t i = 0; i < layout->region_count; i++) {
        const AppleModernBootRegion *r = &layout->regions[i];
        view = prop_view(output, "/chosen/memory-map", r->name);
        assert(view.size == 16 && get64(view.data) == r->physical_address &&
               get64(view.data + 8) == r->size);
    }
    view = prop_view(output, "/chosen", "dram-base");
    assert(view.size == 8 && get64(view.data) == layout->dram_base);
    view = prop_view(output, "/chosen", "dram-size");
    assert(view.size == 8 && get64(view.data) == layout->dram_size);
    view = prop_view(output, "/chosen/memory-map", "SPTM-entry");
    assert(view.size == 16 && get64(view.data) == layout->image_entry_virtual[1]);
    view = prop_view(output, "/chosen/memory-map", "BootKC-virt");
    assert(view.size == 16 && get64(view.data) == layout->image_virtual_base[0]);
    view = prop_view(output, "/chosen/memory-map", "slide");
    assert(view.size == 16 && !get64(view.data) && !get64(view.data + 8));
    checks++;
}

static void same_property(const AppleModernBootInput *input,
                          const AppleModernBootMetadata *output,
                          const char *path, const char *name)
{
    AppleModernBlob original, prepared = prop_view(output, path, name);
    Error *error = NULL;
    assert(apple_modern_adt_property(input->dtree, path, name, &original, &error));
    assert(!error && original.size == prepared.size &&
           !memcmp(original.data, prepared.data, original.size));
    checks++;
}

static void dump_file(const char *directory, const char *name,
                      const void *data, size_t size)
{
    char path[4096];
    FILE *f;
    assert(snprintf(path, sizeof(path), "%s/%s", directory, name) < (int)sizeof(path));
    f = fopen(path, "wbx"); assert(f);
    assert(fwrite(data, 1, size, f) == size && !fclose(f));
}

static void verify_framebuffer_metadata(
    const AppleModernBootMetadataInput *input,
    const AppleModernBootMetadata *baseline)
{
    AppleModernBootInput changed = *input->components;
    AppleModernBootMetadataInput configured = *input, bad;
    AppleModernBootMetadata output = {0}, repeated = {0};
    AppleModernBlob view;
    Error *error = NULL;
    configured.components = &changed;
    /* Existing explicit ABI callers retain their values when disabled. */
    configured.video = (AppleModernBootVideo){0x1234, 1, 128, 32, 24, 32};
    assert(apple_modern_boot_metadata_build(&configured, &output, &error));
    verify_metadata(&configured, &output);
    apple_modern_boot_metadata_clear(&output);
    configured.video = (AppleModernBootVideo){0};
    changed.framebuffer_width = 17;
    changed.framebuffer_height = 3;
    assert(apple_modern_boot_metadata_build(&configured, &output, &error));
    uint64_t framebuffer_base = baseline->layout.dram_base +
        (input->has_mte ? baseline->layout.dram_size / 32 * 31 :
                          baseline->layout.dram_size) -
        APPLE_MODERN_FRAMEBUFFER_ALIGNMENT;
    assert(!error && output.layout.framebuffer_physical ==
           framebuffer_base &&
           output.layout.framebuffer_size == APPLE_MODERN_FRAMEBUFFER_ALIGNMENT &&
           output.layout.top_of_kernel_data ==
           baseline->layout.top_of_kernel_data);
    verify_metadata(&configured, &output);
    const uint64_t expected_video[] = {
        framebuffer_base, 0, 68, 17, 3, 32,
    };
    for (size_t i = 0; i < 6; i++) {
        assert(get64(output.bootargs + 40 + i * 8) == expected_video[i]);
    }
    checks++;
    /* No graphics driver node is synthesized into the original tree. */
    assert(!apple_modern_adt_property(
        (AppleModernBlob){output.dtree, output.dtree_size},
        "/vram", "reg", &view, &error));
    assert(error && !view.data && !view.size);
    error_free(error); error = NULL; checks++;
    assert(apple_modern_boot_metadata_build(&configured, &repeated, &error));
    assert(output.dtree != repeated.dtree &&
           output.dtree_size == repeated.dtree_size &&
           !memcmp(output.dtree, repeated.dtree, output.dtree_size) &&
           !memcmp(output.bootargs, repeated.bootargs, sizeof(output.bootargs)));
    apple_modern_boot_metadata_clear(&repeated); checks++;
    /* Every explicit Video field must agree with the same reservation. */
    configured.video = (AppleModernBootVideo){expected_video[0], 0, 68, 17, 3, 32};
    assert(apple_modern_boot_metadata_build(&configured, &repeated, &error));
    verify_metadata(&configured, &repeated);
    apple_modern_boot_metadata_clear(&repeated);
    bad = configured; bad.video.base_address += PAGE;
    rejected_metadata("framebuffer explicit base conflict", &bad);
    bad = configured; bad.video.display = 1;
    rejected_metadata("framebuffer explicit console mode conflict", &bad);
    bad = configured; bad.video.row_bytes += 4;
    rejected_metadata("framebuffer explicit stride conflict", &bad);
    bad = configured; bad.video.width++;
    rejected_metadata("framebuffer explicit width conflict", &bad);
    bad = configured; bad.video.height++;
    rejected_metadata("framebuffer explicit height conflict", &bad);
    bad = configured; bad.video.depth = 24;
    rejected_metadata("framebuffer explicit format conflict", &bad);
    configured.video = (AppleModernBootVideo){0};
    uint64_t saved_dram_size = changed.dram_size;
    /* Full DRAM accommodates this reservation; the MTE-adjusted range does not. */
    changed.dram_size = UINT64_C(128) << 20;
    changed.framebuffer_width = 4096; changed.framebuffer_height = 896;
    AppleModernBootLayout physical_layout;
    assert(apple_modern_boot_layout_build(&changed, &physical_layout, &error));
    assert(!error && physical_layout.top_of_kernel_data <=
           physical_layout.framebuffer_physical);
    rejected_metadata("framebuffer outside MTE usable RAM", &configured);
    changed.dram_size = saved_dram_size;
    changed.framebuffer_width = 17;
    apple_modern_boot_metadata_clear(&output);
    changed.framebuffer_height = 4096;
    changed.framebuffer_stride = 1024;
    changed.ramdisk = (AppleModernBlob){changed.bootkc.data, 1};
    assert(apple_modern_boot_metadata_build(&configured, &output, &error));
    assert(output.layout.framebuffer_physical ==
           framebuffer_base - APPLE_MODERN_FRAMEBUFFER_ALIGNMENT &&
           output.layout.framebuffer_size == 2 * APPLE_MODERN_FRAMEBUFFER_ALIGNMENT &&
           get64(output.bootargs + 56) == 1024 &&
           output.layout.top_of_kernel_data ==
           baseline->layout.top_of_kernel_data + PAGE);
    verify_metadata(&configured, &output);
    apple_modern_boot_metadata_clear(&output);
    changed.ramdisk = (AppleModernBlob){0};
    /* An existing /vram node keeps unrelated properties, and receives reg. */
    uint8_t *dt = (uint8_t *)changed.dtree.data;
    size_t vram_begin = changed.dtree.size, cursor = vram_begin;
    put32(dt + 4, 4);
    put32(dt + cursor, 3); put32(dt + cursor + 4, 0); cursor += 8;
    prop(dt, &cursor, "name", "vram");
    prop(dt, &cursor, "compatible", "unchanged boot video");
    size_t vram_without_reg = cursor;
    prop(dt, &cursor, "reg", "old firmware address");
    changed.dtree.size = cursor;
    assert(apple_modern_boot_metadata_build(&configured, &output, &error));
    verify_metadata(&configured, &output);
    view = prop_view(&output, "/vram", "reg");
    assert(view.size == 16 &&
           get64(view.data) == output.layout.framebuffer_physical &&
           get64(view.data + 8) == output.layout.framebuffer_size);
    same_property(&changed, &output, "/vram", "compatible"); checks++;
    apple_modern_boot_metadata_clear(&output);
    put32(dt + vram_begin, 2); changed.dtree.size = vram_without_reg;
    assert(apple_modern_boot_metadata_build(&configured, &output, &error));
    view = prop_view(&output, "/vram", "reg");
    assert(view.size == 16 &&
           get64(view.data) == output.layout.framebuffer_physical &&
           get64(view.data + 8) == output.layout.framebuffer_size);
    same_property(&changed, &output, "/vram", "compatible"); checks++;
    apple_modern_boot_metadata_clear(&output);
    size_t vram_bytes = changed.dtree.size - vram_begin;
    memcpy(dt + changed.dtree.size, dt + vram_begin, vram_bytes);
    changed.dtree.size += vram_bytes; put32(dt + 4, 5);
    rejected_metadata("framebuffer duplicate vram path", &configured);
    /* Restore the shared fixture's original root child count. */
    put32(dt + 4, 3);
}

int main(int argc, char **argv)
{
    AppleModernBootInput components = metadata_fixture(), changed;
    AppleModernBootMetadataInput input = {.components = &components,
        .command_line = "-v serial=3", .command_line_length = 11,
        .has_mte = true, .boot_flags = 1}, bad;
    AppleModernBootMetadata output = {0}, repeated = {0};
    AppleModernBlob view;
    Error *error = NULL;
    uint8_t *original_dt = malloc(components.dtree.size);
    uint8_t *ramdisk = calloc(1, 37);
    uint8_t *alias_storage = calloc(1, sizeof(AppleModernBootMetadata));
    char long_command[1024];
    setvbuf(stdout, NULL, _IONBF, 0);
    assert(original_dt && ramdisk && alias_storage);
    ramdisk[0] = 1; ramdisk[1] = 2; ramdisk[2] = 3;
    memcpy(original_dt, components.dtree.data, components.dtree.size);
    assert(apple_modern_boot_metadata_build(&input, &output, &error));
    assert(!error); verify_metadata(&input, &output);
    verify_framebuffer_metadata(&input, &output);
    same_property(&components, &output, "/", "unchanged-root");
    same_property(&components, &output, "/arm-io/sgx", "compatible");
    same_property(&components, &output, "/cpus/cpu0", "state");
    same_property(&components, &output, "/chosen", "secure-boot");
    same_property(&components, &output, "/chosen/memory-map", "MemoryMapReserved-0");
    view = prop_view(&output, "/chosen/memory-map", "RAMDisk");
    assert(get64(view.data) == UINT64_MAX && get64(view.data + 8) == UINT64_MAX); checks++;
    assert(!memcmp(original_dt, components.dtree.data, components.dtree.size)); checks++;
    assert(apple_modern_boot_metadata_build(&input, &repeated, &error));
    assert(output.dtree != repeated.dtree &&
           !memcmp(output.dtree, repeated.dtree, output.dtree_size) &&
           !memcmp(output.bootargs, repeated.bootargs, sizeof(output.bootargs)));
    checks++; apple_modern_boot_metadata_clear(&repeated);
    memset(long_command, 'x', sizeof(long_command));
    bad = input; bad.command_line = long_command; bad.command_line_length = 1023;
    assert(apple_modern_boot_metadata_build(&bad, &repeated, &error));
    verify_metadata(&bad, &repeated);
    assert(!repeated.bootargs[108 + 1023]);
    apple_modern_boot_metadata_clear(&repeated);
    bad = input; bad.command_line = NULL; bad.command_line_length = 0;
    assert(apple_modern_boot_metadata_build(&bad, &repeated, &error));
    verify_metadata(&bad, &repeated); apple_modern_boot_metadata_clear(&repeated);
    bad = input; bad.dtree_capacity_limit = components.dtree.size;
    rejected_metadata("insufficient serialized ADT capacity", &bad);
    bad.dtree_capacity_limit = output.layout.dtree_capacity + 1;
    rejected_metadata("capacity exceeds reserved DRAM", &bad);
    bad = input; bad.command_line = long_command; bad.command_line_length = sizeof(long_command);
    rejected_metadata("long command line", &bad);
    bad = input; bad.command_line = "a\0b"; bad.command_line_length = 3;
    rejected_metadata("embedded command NUL", &bad);
    bad.command_line = NULL; rejected_metadata("missing command bytes", &bad);
    changed = components; changed.dtree.size--; bad = input; bad.components = &changed;
    rejected_metadata("truncated original ADT", &bad);
    changed = components; changed.trustcache.size--; bad.components = &changed;
    rejected_metadata("truncated stock trustcache", &bad);
    changed = components; changed.dtree.size = fixture_chosen_start;
    put32((uint8_t *)changed.dtree.data + 4, 2);
    bad.components = &changed; rejected_metadata("missing chosen path", &bad);
    put32((uint8_t *)changed.dtree.data + 4, 3);
    /* An existing chosen node without memory-map receives only that child. */
    changed = components;
    size_t chosen_props_end = fixture_chosen_start + 8;
    for (unsigned i = 0; i < 3; i++) {
        uint32_t length = (uint32_t)get64(changed.dtree.data + chosen_props_end + 32) & 0x7fffffff;
        chosen_props_end += 36 + ((length + 3) & ~3U);
    }
    changed.dtree.size = chosen_props_end;
    put32((uint8_t *)changed.dtree.data + fixture_chosen_start + 4, 0);
    bad = input; bad.components = &changed;
    assert(apple_modern_boot_metadata_build(&bad, &repeated, &error));
    verify_metadata(&bad, &repeated); apple_modern_boot_metadata_clear(&repeated);
    put32((uint8_t *)changed.dtree.data + fixture_chosen_start + 4, 1);
    /* Duplicate memory-map nodes are ambiguous even when individually bounded. */
    size_t map_bytes = components.dtree.size - chosen_props_end;
    memcpy((uint8_t *)components.dtree.data + components.dtree.size,
           components.dtree.data + chosen_props_end, map_bytes);
    changed = components; changed.dtree.size += map_bytes;
    put32((uint8_t *)changed.dtree.data + fixture_chosen_start + 4, 2);
    bad.components = &changed; rejected_metadata("duplicate memory-map path", &bad);
    put32((uint8_t *)changed.dtree.data + fixture_chosen_start + 4, 1);
    changed = components; changed.ramdisk = (AppleModernBlob){NULL, 1};
    bad.components = &changed; rejected_metadata("missing optional ramdisk bytes", &bad);
    changed.ramdisk = (AppleModernBlob){ramdisk, 0};
    rejected_metadata("empty non-NULL ramdisk", &bad);
    changed.ramdisk = (AppleModernBlob){ramdisk, APPLE_MODERN_MAX_RAMDISK_SIZE + 1};
    rejected_metadata("oversized ramdisk", &bad);
    changed = components; changed.dram_size = output.layout.top_of_kernel_data - output.layout.dram_base;
    bad.components = &changed; rejected_metadata("metadata outside MTE usable RAM", &bad);
    changed = components; changed.ramdisk = (AppleModernBlob){ramdisk, 37};
    bad = input; bad.components = &changed;
    assert(apple_modern_boot_metadata_build(&bad, &repeated, &error));
    assert(repeated.layout.region_count == 20 && repeated.layout.copy_count == 25 &&
           repeated.layout.ramdisk_size == 37 &&
           repeated.layout.ramdisk_physical == output.layout.top_of_kernel_data &&
           repeated.layout.top_of_kernel_data == output.layout.top_of_kernel_data + PAGE);
    verify_metadata(&bad, &repeated); apple_modern_boot_metadata_clear(&repeated);
    assert(!apple_modern_adt_property(components.dtree, "/missing", "name", &view, &error));
    assert(error && !view.data && !view.size); error_free(error); error = NULL; checks++;
    assert(!apple_modern_adt_property((AppleModernBlob){components.dtree.data, components.dtree.size - 1},
                                    "/", "name", &view, &error));
    assert(error && !view.data && !view.size); error_free(error); error = NULL; checks++;
    assert(!apple_modern_boot_metadata_build(&input,
           (AppleModernBootMetadata *)components.dtree.data, &error));
    assert(error && !memcmp(original_dt, components.dtree.data, components.dtree.size));
    error_free(error); error = NULL; checks++;
    assert(!apple_modern_boot_layout_build(&components,
           (AppleModernBootLayout *)components.dtree.data, &error));
    assert(error && !memcmp(original_dt, components.dtree.data, components.dtree.size));
    error_free(error); error = NULL; checks++;
    assert(!apple_modern_adt_property(components.dtree, "/", "name",
           (AppleModernBlob *)components.dtree.data, &error));
    assert(error && !memcmp(original_dt, components.dtree.data, components.dtree.size));
    error_free(error); error = NULL; checks++;
    strcpy((char *)alias_storage, "/");
    assert(!apple_modern_adt_property(components.dtree, (char *)alias_storage, "name",
           (AppleModernBlob *)alias_storage, &error));
    assert(error && !strcmp((char *)alias_storage, "/"));
    error_free(error); error = NULL; checks++;
    memset(alias_storage, 0, sizeof(AppleModernBootMetadata));
    memcpy(alias_storage, &input, sizeof(input));
    assert(!apple_modern_boot_metadata_build((AppleModernBootMetadataInput *)alias_storage,
           (AppleModernBootMetadata *)alias_storage, &error));
    assert(error && !memcmp(alias_storage, &input, sizeof(input)));
    error_free(error); error = NULL; checks++;
    memset(alias_storage, 0, sizeof(AppleModernBootMetadata));
    memcpy(alias_storage, &components, sizeof(components));
    bad = input; bad.components = (AppleModernBootInput *)alias_storage;
    assert(!apple_modern_boot_metadata_build(&bad, (AppleModernBootMetadata *)alias_storage, &error));
    assert(error && !memcmp(alias_storage, &components, sizeof(components)));
    error_free(error); error = NULL; checks++;
    apple_modern_boot_metadata_clear(&output);
    apple_modern_boot_metadata_clear(&output);
    assert(!memcmp(&output, &repeated, sizeof(output))); checks++;
    free(original_dt); free(ramdisk); free(alias_storage); free_components(&components);
    if (argc >= 2) {
        AppleModernBootInput actual = {.dram_base = UINT64_C(1) << 40,
                                      .dram_size = UINT64_C(8) << 30};
        actual.bootkc = file(argv[1], "bootkc"); actual.sptm = file(argv[1], "sptm");
        actual.txm = file(argv[1], "txm"); actual.dtree = file(argv[1], "dtree");
        actual.trustcache = file(argv[1], "restore-trustcache");
        AppleModernBlob original[5] = {actual.bootkc, actual.sptm, actual.txm,
                                      actual.dtree, actual.trustcache};
        uint8_t *saved[5];
        for (size_t i = 0; i < 5; i++) {
            saved[i] = malloc(original[i].size); assert(saved[i]);
            memcpy(saved[i], original[i].data, original[i].size);
        }
        input.components = &actual;
        if (!apple_modern_boot_metadata_build(&input, &output, &error)) {
            fprintf(stderr, "%s\n", error ? error->message : "failure without error");
            return 1;
        }
        verify_metadata(&input, &output);
        same_property(&actual, &output, "/arm-io", "compatible");
        same_property(&actual, &output, "/arm-io/sgx", "compatible");
        same_property(&actual, &output, "/chosen", "secure-boot");
        same_property(&actual, &output, "/chosen/memory-map", "MemoryMapReserved-0");
        for (size_t i = 0; i < 5; i++) {
            assert(!memcmp(saved[i], original[i].data, original[i].size));
            free(saved[i]);
        }
        checks++;
        printf("ACTUAL nodes=%u filesets=%u regions=%zu copies=%zu dtree_size=%zu "
               "bootargs_size=%zu trustcache_size=%zu\n", output.layout.dtree_node_count,
               output.layout.fileset_entry_count, output.layout.region_count,
               output.layout.copy_count, output.dtree_size, sizeof(output.bootargs),
               output.trustcache_size);
        if (argc == 3) {
            dump_file(argv[2], "prepared-dtree", output.dtree, output.dtree_size);
            dump_file(argv[2], "prepared-bootargs", output.bootargs, sizeof(output.bootargs));
            dump_file(argv[2], "prepared-trustcache", output.trustcache, output.trustcache_size);
        }
        apple_modern_boot_metadata_clear(&output); free_components(&actual);
    }
    printf("PASS %u metadata semantic checks; no guest writes or execution\n", checks);
    return 0;
}
