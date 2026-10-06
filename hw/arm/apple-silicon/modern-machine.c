/*
 * Modern Apple boot integration experiment: RAM, metadata, CPU registers, UART.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This is not a complete T8140 platform. Its default prepares memory and halts
 * the CPU. The guarded CPU compatibility profile is enabled, while remaining
 * platform devices are separate implementation gates. No executable bytes or
 * guest policy are patched here.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "hw/boards.h"
#include "hw/core/cpu.h"
#include "hw/arm/boot.h"
#include "hw/arm/apple-silicon/modern-boot-metadata.h"
#include "hw/arm/apple-silicon/modern-board-regions.h"
#include "hw/char/apple_uart.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "system/system.h"
#include "cpu.h"

#define TYPE_APPLE_MODERN_MACHINE MACHINE_TYPE_NAME("apple-modern")
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMachine, APPLE_MODERN_MACHINE)

enum ModernAsset {
    ASSET_BOOTKC, ASSET_SPTM, ASSET_TXM, ASSET_DTREE, ASSET_TC, ASSET_RAMDISK,
    ASSET_COUNT,
};

struct AppleModernMachine {
    MachineState parent_obj;
    char *paths[ASSET_COUNT];
    char *boot_command_line;
    AppleModernBlob blobs[ASSET_COUNT];
    AppleModernBootInput components;
    AppleModernBootMetadata metadata;
    AppleModernBoardRegions board_regions;
    ARMCPU *cpu;
    MemoryRegion ram, tag_memory, tag_ram;
    MemoryRegion cpu_register_ram[APPLE_MODERN_CPU_REGISTER_WINDOWS];
    bool prepare_only, mte, initialized;
    uint64_t timebase_frequency;
};

static bool read_asset(const char *path, AppleModernBlob *blob,
                       size_t budget, Error **errp)
{
    struct stat before, after;
    uint8_t *bytes;
    size_t done = 0, expected;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) {
        error_setg_errno(errp, errno, "cannot open modern boot asset %s", path);
        return false;
    }
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size <= 0 ||
        before.st_size > (512 * MiB) || (uint64_t)before.st_size > budget) {
        error_setg(errp, "modern asset must be a regular nonempty file of at "
                   "most 512 MiB within the 1 GiB total input budget: %s", path);
        close(fd);
        return false;
    }
    expected = before.st_size;
    bytes = g_malloc(expected);
    while (done < expected) {
        ssize_t amount = read(fd, bytes + done, expected - done);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            error_setg(errp, "incomplete modern boot asset: %s", path);
            g_free(bytes);
            close(fd);
            return false;
        }
        done += amount;
    }
    if (fstat(fd, &after) || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        error_setg(errp, "modern boot asset changed while reading: %s", path);
        g_free(bytes);
        close(fd);
        return false;
    }
    close(fd);
    *blob = (AppleModernBlob){ bytes, done };
    return true;
}

static void write_memory(uint64_t address, const void *bytes, size_t size)
{
    if (address_space_write(&address_space_memory, address,
                            MEMTXATTRS_UNSPECIFIED, bytes, size) != MEMTX_OK) {
        error_report("apple-modern boot write failed at 0x%" PRIx64, address);
        exit(EXIT_FAILURE);
    }
}

static void load_prepared_memory(AppleModernMachine *s)
{
    AppleModernBootLayout *layout = &s->metadata.layout;
    AppleModernBlob sources[] = { s->components.bootkc, s->components.sptm,
                                  s->components.txm, s->components.trustcache,
                                  s->components.ramdisk };

    /* Reservations and BSS are restored on reset, not left as prior guest data. */
    for (size_t i = 0; i < layout->region_count; i++) {
        AppleModernBootRegion *r = &layout->regions[i];
        if (address_space_set(&address_space_memory, r->physical_address, 0,
                              r->size, MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            error_report("apple-modern region initialization failed");
            exit(EXIT_FAILURE);
        }
        if (!strcmp(r->name, "TrustCache")) {
            write_memory(r->physical_address, s->metadata.trustcache,
                         s->metadata.trustcache_size);
        }
    }
    for (size_t i = 0; i < layout->copy_count; i++) {
        AppleModernBootCopy *copy = &layout->copies[i];
        AppleModernBlob source = sources[copy->image];
        if (copy->image == APPLE_MODERN_TRUSTCACHE) {
            continue; /* Written above with the normal offsets header. */
        }
        write_memory(copy->physical_address, source.data + copy->source_offset,
                     copy->file_size);
    }
    write_memory(layout->dtree_physical, s->metadata.dtree, s->metadata.dtree_size);
    write_memory(layout->bootargs_physical, s->metadata.bootargs,
                 sizeof(s->metadata.bootargs));
    for (size_t i = 0; i < s->board_regions.count; i++) {
        AppleModernBoardRegion *r = &s->board_regions.windows[i];
        if (address_space_set(&address_space_memory, r->physical_address, 0,
                              r->size, MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            error_report("apple-modern register window reset failed");
            exit(EXIT_FAILURE);
        }
    }
}

static void modern_reset(void *opaque)
{
    AppleModernMachine *s = opaque;
    CPUState *cs = CPU(s->cpu);
    CPUARMState *env = &s->cpu->env;

    cpu_reset(cs);
    assert(arm_highest_el(env) == 2);
    load_prepared_memory(s);
    env->pc = s->metadata.layout.sptm_entry_physical;
    env->xregs[0] = s->metadata.layout.bootargs_physical;
    env->cp15.cpacr_el1 |= 3U << 20; /* Ordinary FP/SIMD enable. */
    env->cp15.cptr_el[2] &= ~(1U << 10); /* CPTR_EL2.TFP. */
    cs->halted = s->prepare_only;
    arm_rebuild_hflags(env);
}

static bool uart_address(AppleModernBlob dtree, uint64_t *address,
                         uint64_t *span, Error **errp)
{
    AppleModernBlob ranges, reg, compatible;
    uint64_t offset, size;

    if (!apple_modern_adt_property(dtree, "/arm-io", "ranges", &ranges, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/uart0", "reg", &reg, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/uart0", "compatible",
                                   &compatible, errp)) {
        return false;
    }
    if (!ranges.size || ranges.size % 24 || reg.size != 16 ||
        compatible.size != sizeof("uart-1,samsung") ||
        memcmp(compatible.data, "uart-1,samsung", sizeof("uart-1,samsung"))) {
        error_setg(errp, "unsupported modern UART ADT schema");
        return false;
    }
    offset = ldq_le_p(reg.data);
    size = ldq_le_p(reg.data + 8);
    if (size < 0x3c) {
        error_setg(errp, "modern UART register span is too small");
        return false;
    }
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t child = ldq_le_p(ranges.data + i);
        uint64_t parent = ldq_le_p(ranges.data + i + 8);
        uint64_t length = ldq_le_p(ranges.data + i + 16);
        if (offset >= child && offset - child <= length &&
            size <= length - (offset - child) &&
            parent <= UINT64_MAX - (offset - child) &&
            parent + (offset - child) <= UINT64_MAX - size) {
            *address = parent + (offset - child);
            *span = size;
            return true;
        }
    }
    error_setg(errp, "modern UART is outside the ADT bus ranges");
    return false;
}

static void modern_init(MachineState *machine)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(machine);
    AppleModernBootMetadataInput metadata_input = {0};
    uint64_t uart, uart_span;
    size_t asset_budget = GiB;
    Error *error = NULL;

    if (machine->smp.cpus != 1 || machine->kernel_filename ||
        machine->dtb || machine->initrd_filename) {
        error_report("apple-modern uses one CPU and explicit decoded machine "
                     "assets; -kernel/-dtb/-initrd are not accepted");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < ASSET_COUNT; i++) {
        if (i == ASSET_RAMDISK && !s->paths[i]) {
            continue;
        }
        if (!s->paths[i] || !read_asset(s->paths[i], &s->blobs[i],
                                       asset_budget, &error)) {
            if (!error) {
                error_setg(&error, "apple-modern requires bootkc, sptm, txm, "
                           "dtree and tc machine properties");
            }
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        asset_budget -= s->blobs[i].size;
    }
    s->components = (AppleModernBootInput){
        .bootkc = s->blobs[ASSET_BOOTKC], .sptm = s->blobs[ASSET_SPTM],
        .txm = s->blobs[ASSET_TXM], .dtree = s->blobs[ASSET_DTREE],
        .trustcache = s->blobs[ASSET_TC], .ramdisk = s->blobs[ASSET_RAMDISK],
        .dram_base = UINT64_C(1) << 40, .dram_size = machine->ram_size,
    };
    metadata_input.components = &s->components;
    metadata_input.command_line = s->boot_command_line;
    metadata_input.command_line_length = s->boot_command_line ?
                                         strlen(s->boot_command_line) : 0;
    metadata_input.has_mte = s->mte;
    if (!apple_modern_boot_metadata_build(&metadata_input, &s->metadata, &error) ||
        !uart_address(s->components.dtree, &uart, &uart_span, &error)) {
        error_report_err(error);
        exit(EXIT_FAILURE);
    }
    AppleModernAddressRange exclusion = { uart, uart_span };
    if (!apple_modern_board_regions_build(s->components.dtree,
                                          s->components.dram_base,
                                          s->components.dram_size,
                                          &exclusion, 1, &s->board_regions,
                                          &error)) {
        error_report_err(error);
        exit(EXIT_FAILURE);
    }
    /* Migratable RAM's owner must be a DeviceState or NULL, not MachineState. */
    memory_region_init_ram(&s->ram, NULL, "apple-modern.ram",
                           machine->ram_size, &error_fatal);
    memory_region_add_subregion(get_system_memory(), s->components.dram_base,
                                &s->ram);
    for (size_t i = 0; i < s->board_regions.count; i++) {
        AppleModernBoardRegion *r = &s->board_regions.windows[i];
        memory_region_init_ram(&s->cpu_register_ram[i], NULL, r->name,
                               r->size, &error_fatal);
        memory_region_add_subregion(get_system_memory(), r->physical_address,
                                    &s->cpu_register_ram[i]);
    }
    s->cpu = ARM_CPU(object_new(machine->cpu_type));
    object_property_add_child(OBJECT(s), "cpu", OBJECT(s->cpu));
    object_unref(OBJECT(s->cpu));
    object_property_set_bool(OBJECT(s->cpu), "has_el2", true, &error_fatal);
    object_property_set_bool(OBJECT(s->cpu), "has_el3", false, &error_fatal);
    object_property_set_bool(OBJECT(s->cpu), "pauth-noop", false, &error_fatal);
    object_property_set_bool(OBJECT(s->cpu), "apple-modern-gxf", true, &error_fatal);
    object_property_set_bool(OBJECT(s->cpu), "apple-modern-timers", true,
                              &error_fatal);
    object_property_set_bool(OBJECT(s->cpu), "apple-modern-guarded", true,
                              &error_fatal);
    object_property_set_bool(OBJECT(s->cpu), "apple-modern-sprr", true,
                              &error_fatal);
    object_property_set_uint(OBJECT(s->cpu), "cntfrq", s->timebase_frequency,
                             &error_fatal);
    object_property_set_link(OBJECT(s->cpu), "memory", OBJECT(get_system_memory()),
                             &error_fatal);
    if (s->mte) {
        memory_region_init(&s->tag_memory, OBJECT(s), "apple-modern.tags",
                           UINT64_MAX / 32);
        memory_region_init_ram(&s->tag_ram, NULL, "apple-modern.tag-ram",
                               machine->ram_size / 32, &error_fatal);
        memory_region_add_subregion(&s->tag_memory, s->components.dram_base / 32,
                                    &s->tag_ram);
        object_property_set_link(OBJECT(s->cpu), "tag-memory",
                                 OBJECT(&s->tag_memory), &error_fatal);
    }
    qdev_realize(DEVICE(s->cpu), NULL, &error_fatal);
    qdev_connect_gpio_out(DEVICE(s->cpu), GTIMER_HYPVIRT,
                          qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_FIQ));
    /* Serial polling only until a real modern interrupt controller is wired. */
    apple_uart_create(uart, 15, 0, serial_hd(0), NULL);
    qemu_register_reset(modern_reset, s);
    s->initialized = true;
}

static bool check_mutable(AppleModernMachine *s, Error **errp)
{
    if (s->initialized) {
        error_setg(errp, "apple-modern properties are fixed after initialization");
        return false;
    }
    return true;
}

static char *get_boot_command_line(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->boot_command_line);
}

static void set_boot_command_line(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->boot_command_line);
        s->boot_command_line = g_strdup(value);
    }
}

#define ASSET_PROPERTY(name, index) \
    static char *get_##name(Object *obj, Error **errp) \
    { return g_strdup(APPLE_MODERN_MACHINE(obj)->paths[index]); } \
    static void set_##name(Object *obj, const char *value, Error **errp) \
    { \
        AppleModernMachine *s = APPLE_MODERN_MACHINE(obj); \
        if (check_mutable(s, errp)) { \
            g_free(s->paths[index]); s->paths[index] = g_strdup(value); \
        } \
    }
ASSET_PROPERTY(bootkc, ASSET_BOOTKC)
ASSET_PROPERTY(sptm, ASSET_SPTM)
ASSET_PROPERTY(txm, ASSET_TXM)
ASSET_PROPERTY(dtree, ASSET_DTREE)
ASSET_PROPERTY(tc, ASSET_TC)
ASSET_PROPERTY(ramdisk, ASSET_RAMDISK)
#undef ASSET_PROPERTY

#define BOOL_PROPERTY(name, field) \
    static bool get_##name(Object *obj, Error **errp) \
    { return APPLE_MODERN_MACHINE(obj)->field; } \
    static void set_##name(Object *obj, bool value, Error **errp) \
    { AppleModernMachine *s = APPLE_MODERN_MACHINE(obj); \
      if (check_mutable(s, errp)) { s->field = value; } }
BOOL_PROPERTY(prepare_only, prepare_only)
BOOL_PROPERTY(mte, mte)
#undef BOOL_PROPERTY

static void get_frequency(Object *obj, Visitor *visitor, const char *name,
                           void *opaque, Error **errp)
{
    uint64_t value = APPLE_MODERN_MACHINE(obj)->timebase_frequency;
    visit_type_uint64(visitor, name, &value, errp);
}

static void set_frequency(Object *obj, Visitor *visitor, const char *name,
                           void *opaque, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    uint64_t value;
    if (!check_mutable(s, errp) || !visit_type_uint64(visitor, name, &value, errp)) {
        return;
    }
    if (!value || value > 1000000000) {
        error_setg(errp, "timebase-frequency must be from 1 to 1000000000 Hz");
        return;
    }
    s->timebase_frequency = value;
}

static void modern_instance_init(Object *obj)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    s->prepare_only = true;
    s->timebase_frequency = 24000000; /* Configurable experiment value. */
}

static void modern_finalize(Object *obj)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    apple_modern_boot_metadata_clear(&s->metadata);
    g_free(s->boot_command_line);
    for (size_t i = 0; i < ASSET_COUNT; i++) {
        g_free(s->paths[i]);
        g_free((void *)s->blobs[i].data);
    }
}

static void modern_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    mc->desc = "Modern Apple boot experiment (RAM/registers/UART; no GUI)";
    mc->init = modern_init;
    mc->max_cpus = 1;
    mc->default_ram_size = 8 * GiB;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("max");
    object_class_property_add_str(oc, "bootkc", get_bootkc, set_bootkc);
    object_class_property_add_str(oc, "sptm", get_sptm, set_sptm);
    object_class_property_add_str(oc, "txm", get_txm, set_txm);
    object_class_property_add_str(oc, "dtree", get_dtree, set_dtree);
    object_class_property_add_str(oc, "tc", get_tc, set_tc);
    object_class_property_add_str(oc, "ramdisk", get_ramdisk, set_ramdisk);
    object_class_property_add_str(oc, "boot-command-line", get_boot_command_line,
                                  set_boot_command_line);
    object_class_property_add_bool(oc, "prepare-only", get_prepare_only, set_prepare_only);
    object_class_property_add_bool(oc, "mte", get_mte, set_mte);
    object_class_property_add(oc, "timebase-frequency", "uint64",
                              get_frequency, set_frequency, NULL, NULL);
}

static const TypeInfo modern_type = {
    .name = TYPE_APPLE_MODERN_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(AppleModernMachine),
    .instance_init = modern_instance_init,
    .instance_finalize = modern_finalize,
    .class_init = modern_class_init,
};

static void register_modern_machine(void)
{
    type_register_static(&modern_type);
}
type_init(register_modern_machine);
