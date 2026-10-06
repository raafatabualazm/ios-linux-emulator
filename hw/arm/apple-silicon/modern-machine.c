/*
 * Modern Apple boot integration experiment: RAM, metadata, CPU registers, UART.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This is not a complete T8140 platform. Its default prepares memory and halts
 * the CPU. Platform devices are separate implementation gates. Existing
 * ignition/PAC compatibility modes are explicitly opt-in; see their helpers.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "hw/boards.h"
#include "hw/core/cpu.h"
#include "hw/arm/boot.h"
#include "hw/arm/apple-silicon/modern-boot-metadata.h"
#include "hw/arm/apple-silicon/modern-board-regions.h"
#include "hw/arm/apple-silicon/modern-amcc.h"
#include "hw/arm/apple-silicon/modern-kc-patch.h"
#include "hw/arm/apple-silicon/modern-boot-display.h"
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
    MemoryRegion aic_ram, sep_ram;
    MemoryRegion sep_trace_mr[2];
    unsigned sep_trace_count;
    AppleModernAMCC amcc;
    bool has_amcc;
    bool img4_ignition_compat;
    bool pauth_compat;
    bool sep_trace;
    bool boot_display;
    bool prepare_only, mte, initialized;
    uint64_t timebase_frequency;
    uint32_t display_width, display_height, display_stride;
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

/*
 * Look up a /chosen/memory-map region in the served (prepared) ADT. first =
 * start of the region; last = start of its final 4 KiB page, as SPTM reads
 * the CTRR/CTXR bounds.
 */
static bool adt_region(AppleModernMachine *s, const char *name,
                       uint64_t *first, uint64_t *last)
{
    AppleModernBlob tree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob value;
    Error *err = NULL;
    uint64_t base, size;

    if (!apple_modern_adt_property(tree, "/chosen/memory-map", name, &value,
                                   &err)) {
        error_report_err(err);
        return false;
    }
    if (value.size < 16) {
        error_report("apple-modern memory-map region %s is too small", name);
        return false;
    }
    base = ldq_le_p(value.data);
    size = ldq_le_p(value.data + 8);
    if (!size || size < 0x1000 || base > UINT64_MAX - size) {
        error_report("apple-modern memory-map region %s is invalid", name);
        return false;
    }
    *first = base;
    *last = base + size - 0x1000;
    return true;
}

/*
 * Port of Darwin-VM apple_regs_init(): seed the CTRR/CTXR bounds and MTE tag
 * offset that SPTM reads back and compares against the regions it stashed from
 * the device tree. Bank C bounds are also mirrored into the AMCC aperture, as
 * in Darwin. Values come from the prepared ADT, not from hardware
 * observation; these are compatibility stores with no enforcement effect.
 * Returns false on a missing region or absent compatibility register.
 */
static bool apply_adt_cpu_registers(AppleModernMachine *s)
{
    static const struct {
        const char *lwr, *upr, *first_region, *last_region;
    } windows[] = {
        { "CTRR_A_LWR_EL2", "CTRR_A_UPR_EL2", "BootKC-rx", "BootKC-rs" },
        { "ACC_CTRR_C_LWR_EL2", "ACC_CTRR_C_UPR_EL2", "DeviceTree", "SPTM-rx" },
        { "ACC_CTXR_A_LWR_EL2", "ACC_CTXR_A_UPR_EL2", "SPTM-rx", "SPTM-rx" },
        { "ACC_CTXR_B_LWR_EL2", "ACC_CTXR_B_UPR_EL2", "CL4-dummypage",
          "CL4-dummypage" },
        { "ACC_CTXR_C_LWR_EL2", "ACC_CTXR_C_UPR_EL2", "TXM-rx", "TXM-bx" },
        { "ACC_CTXR_D_LWR_EL2", "ACC_CTXR_D_UPR_EL2", "BootKC-rx", "BootKC-bx" },
    };
    uint64_t ram = s->components.dram_size;

    for (size_t i = 0; i < ARRAY_SIZE(windows); i++) {
        uint64_t first, last, ignored;

        if (!adt_region(s, windows[i].first_region, &first, &ignored) ||
            !adt_region(s, windows[i].last_region, &ignored, &last)) {
            return false;
        }
        if (s->has_amcc && !strcmp(windows[i].lwr, "ACC_CTRR_C_LWR_EL2")) {
            apple_modern_amcc_set_bounds(&s->amcc, APPLE_MODERN_AMCC_BANK_C,
                                         first, last);
        }
        if (!arm_apple_modern_sysreg_set(s->cpu, windows[i].lwr, first) ||
            !arm_apple_modern_sysreg_set(s->cpu, windows[i].upr, last)) {
            error_report("apple-modern missing compatibility register %s",
                         windows[i].lwr);
            return false;
        }
    }
    /* Last 1/32nd of memory, moved forward by another 1/32nd (Darwin). */
    if (!arm_apple_modern_sysreg_set(s->cpu, "TAG_OFFSET_EL2",
            BIT_ULL(63) | (s->components.dram_base + ram - (2 * ram) / 32))) {
        error_report("apple-modern missing TAG_OFFSET_EL2");
        return false;
    }
    return true;
}

static void modern_reset(void *opaque)
{
    AppleModernMachine *s = opaque;
    CPUState *cs = CPU(s->cpu);
    CPUARMState *env = &s->cpu->env;

    cpu_reset(cs);
    assert(arm_highest_el(env) == 2);
    load_prepared_memory(s);
    if (s->has_amcc) {
        apple_modern_amcc_reset(&s->amcc);
    }
    if (!apply_adt_cpu_registers(s)) {
        exit(EXIT_FAILURE);
    }
    env->pc = s->metadata.layout.sptm_entry_physical;
    env->xregs[0] = s->metadata.layout.bootargs_physical;
    env->cp15.cpacr_el1 |= 3U << 20; /* Ordinary FP/SIMD enable. */
    env->cp15.cptr_el[2] &= ~(1U << 10); /* CPTR_EL2.TFP. */
    /*
     * With HCR_EL2.E2H the EL2 trap register uses the CPACR layout, so FPEN
     * must also be set there for EL2 FP/SIMD (as in Darwin-VM's reset).
     */
    env->cp15.cptr_el[2] |= 3U << 20;
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

/* Translate an /arm-io child-relative (offset,size) through the bus ranges. */
static bool arm_io_translate(AppleModernBlob dtree, uint64_t offset,
                             uint64_t size, uint64_t *address, Error **errp)
{
    AppleModernBlob ranges;

    if (!apple_modern_adt_property(dtree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (!ranges.size || ranges.size % 24) {
        error_setg(errp, "unsupported /arm-io ranges schema");
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
            return true;
        }
    }
    error_setg(errp, "device is outside the /arm-io bus ranges");
    return false;
}

static bool adt_u32(AppleModernBlob dtree, const char *path, const char *name,
                    uint32_t *value, Error **errp)
{
    AppleModernBlob prop;

    if (!apple_modern_adt_property(dtree, path, name, &prop, errp)) {
        return false;
    }
    if (prop.size != 4) {
        error_setg(errp, "%s/%s is not a 32-bit value", path, name);
        return false;
    }
    *value = ldl_le_p(prop.data);
    return true;
}

/*
 * Darwin-VM amcc_create(): map the AMCC aperture named by the served ADT
 * (/chosen/lock-regs/amcc) and store only each bank's bound registers. The
 * ADT values are Darwin's dt_fixup synthesis, not a hardware observation.
 * Absent node: no AMCC, as in Darwin.
 */
static bool map_amcc(AppleModernMachine *s, Error **errp)
{
    static const char *const banks[APPLE_MODERN_AMCC_BANKS] = {
        "amcc-ctrr-a", "amcc-ctrr-b", "amcc-ctrr-c", "amcc-ctrr-d",
    };
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob prop;
    uint32_t lwr[APPLE_MODERN_AMCC_BANKS] = {0}, upr[APPLE_MODERN_AMCC_BANKS] = {0};
    uint32_t size;
    uint64_t base;
    Error *local = NULL;

    if (!apple_modern_adt_property(dtree, "/chosen/lock-regs/amcc",
                                   "aperture-phys-addr", &prop, &local)) {
        error_free(local);
        return true;
    }
    if (prop.size != 8) {
        error_setg(errp, "AMCC aperture-phys-addr is not a 64-bit value");
        return false;
    }
    base = ldq_le_p(prop.data);
    if (!adt_u32(dtree, "/chosen/lock-regs/amcc", "aperture-size", &size,
                 errp)) {
        return false;
    }
    for (unsigned bank = 0; bank < APPLE_MODERN_AMCC_BANKS; bank++) {
        char path[64];
        snprintf(path, sizeof(path), "/chosen/lock-regs/amcc/%s", banks[bank]);
        if (!apple_modern_adt_property(dtree, path, "lower-limit-reg-offset",
                                       &prop, &local)) {
            error_free(local);
            local = NULL;
            continue; /* Bank without bound registers. */
        }
        if (!adt_u32(dtree, path, "lower-limit-reg-offset", &lwr[bank], errp) ||
            !adt_u32(dtree, path, "upper-limit-reg-offset", &upr[bank], errp)) {
            return false;
        }
    }
    if (!apple_modern_amcc_init(&s->amcc, get_system_memory(),
                                base, size, lwr, upr, errp)) {
        return false;
    }
    s->has_amcc = true;
    return true;
}

/*
 * Darwin-VM init_aic(): a bare-bones controller that ignores register
 * accesses and only reports the IRQ count. For aic,3 the count lives at
 * aperture offset 0xC. This is a stub, not a functional AIC; interrupts are
 * not delivered. Delivery remains a separate device gate.
 */
#define MODERN_AIC_NUM_IRQS 0x1000
static bool map_aic(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob reg, compatible;
    uint64_t offset, size, base;
    uint32_t num_irqs = MODERN_AIC_NUM_IRQS;

    if (!apple_modern_adt_property(dtree, "/arm-io/aic", "reg", &reg, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/aic", "compatible",
                                   &compatible, errp)) {
        return false;
    }
    if (reg.size != 16 || compatible.size < sizeof("aic,3") ||
        memcmp(compatible.data, "aic,3", sizeof("aic,3"))) {
        error_setg(errp, "unsupported modern AIC ADT schema (expected aic,3)");
        return false;
    }
    offset = ldq_le_p(reg.data);
    size = ldq_le_p(reg.data + 8);
    if (size < 0x10 || size > 0x400000) {
        error_setg(errp, "modern AIC register span is out of range");
        return false;
    }
    if (!arm_io_translate(dtree, offset, size, &base, errp)) {
        return false;
    }
    memory_region_init_ram(&s->aic_ram, NULL, "apple-modern.aic", size,
                           &error_fatal);
    memory_region_add_subregion(get_system_memory(), base, &s->aic_ram);
    cpu_physical_memory_write(base + 0xC, &num_irqs, sizeof(num_irqs));
    return true;
}

/*
/*
 * Observation aperture for the SEP ASC windows named by /arm-io/sep "reg".
 * Opt-in (sep-trace) and default off. It is NOT a device: reads return zero
 * and writes are discarded; every access is logged under -d unimp so the
 * offsets the guest driver actually touches can be measured before any
 * register layout is implemented. The modern wrapper is "iop-sep,ascwrap-v6"
 * and no v6 register map is documented in either source tree.
 */
typedef struct AppleModernSEPTrace {
    uint64_t base;
    unsigned index;
} AppleModernSEPTrace;

static uint64_t sep_trace_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleModernSEPTrace *t = opaque;

    qemu_log_mask(LOG_UNIMP, "SEP-TRACE win%u read  0x%" PRIx64 " +0x%05"
                  PRIx64 " size %u\n", t->index, t->base, (uint64_t)offset,
                  size);
    return 0;
}

static void sep_trace_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size)
{
    AppleModernSEPTrace *t = opaque;

    qemu_log_mask(LOG_UNIMP, "SEP-TRACE win%u write 0x%" PRIx64 " +0x%05"
                  PRIx64 " size %u value 0x%" PRIx64 "\n", t->index, t->base,
                  (uint64_t)offset, size, value);
}

static const MemoryRegionOps sep_trace_ops = {
    .read = sep_trace_read,
    .write = sep_trace_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

/* Map each /arm-io/sep "reg" window as a logging aperture. */
static bool map_sep_trace(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob reg;
    Error *local = NULL;

    if (!apple_modern_adt_property(dtree, "/arm-io/sep", "reg", &reg, &local)) {
        error_free(local);
        return true;
    }
    if (!reg.size || reg.size % 16) {
        error_setg(errp, "unsupported modern SEP reg schema");
        return false;
    }
    for (size_t i = 0; i + 16 <= reg.size; i += 16) {
        uint64_t offset = ldq_le_p(reg.data + i);
        uint64_t size = ldq_le_p(reg.data + i + 8);
        AppleModernSEPTrace *trace;
        uint64_t base;
        char name[32];

        if (s->sep_trace_count >= ARRAY_SIZE(s->sep_trace_mr)) {
            break;
        }
        if (!size || size > 0x1000000) {
            error_setg(errp, "modern SEP register window is out of range");
            return false;
        }
        if (!arm_io_translate(dtree, offset, size, &base, errp)) {
            return false;
        }
        trace = g_new0(AppleModernSEPTrace, 1);
        trace->base = base;
        trace->index = s->sep_trace_count;
        snprintf(name, sizeof(name), "apple-modern.sep-trace%u",
                 s->sep_trace_count);
        memory_region_init_io(&s->sep_trace_mr[s->sep_trace_count],
                              NULL, &sep_trace_ops, trace, name, size);
        memory_region_add_subregion(get_system_memory(), base,
                                    &s->sep_trace_mr[s->sep_trace_count]);
        warn_report("apple-modern: SEP trace window %u at 0x%" PRIx64
                    " size 0x%" PRIx64 " (observation only, not a device)",
                    s->sep_trace_count, base, size);
        s->sep_trace_count++;
    }
    return true;
}

/*
 * Darwin-VM init_sep(): the InvalidateHmac reg-block is mapped as ignored
 * RAM. The served ADT sets sio-hmac1-disable-mask = -1 so InvalidateHmac is
 * effectively disabled as long as these registers can be read and written.
 * The reg-block base is absolute (not /arm-io child-relative). Absent on some
 * trees, in which case nothing is mapped.
 */
static bool map_sep(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob reg;
    uint64_t base, size;
    Error *local = NULL;

    if (!apple_modern_adt_property(dtree,
            "/arm-io/sep/iop-sep-nub/InvalidateHmac", "reg-block", &reg,
            &local)) {
        error_free(local);
        return true; /* Optional: no SEP InvalidateHmac node present. */
    }
    if (reg.size != 16) {
        error_setg(errp, "unsupported modern SEP InvalidateHmac schema");
        return false;
    }
    base = ldq_le_p(reg.data);
    size = ldq_le_p(reg.data + 8);
    if (!size || size > 0x200000) {
        error_setg(errp, "modern SEP InvalidateHmac span is out of range");
        return false;
    }
    memory_region_init_ram(&s->sep_ram, NULL, "apple-modern.sep", size,
                           &error_fatal);
    memory_region_add_subregion(get_system_memory(), base, &s->sep_ram);
    return true;
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
        .framebuffer_width = s->boot_display ? s->display_width : 0,
        .framebuffer_height = s->boot_display ? s->display_height : 0,
        .framebuffer_stride = s->boot_display ? s->display_stride : 0,
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
    if (s->img4_ignition_compat) {
        /*
         * Declared, opt-in guest-kernel compatibility edit on the private
         * in-memory boot kernel cache only. See modern-kc-patch.h. The copy is
         * the one load_prepared_memory() writes into guest RAM at every reset.
         */
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;
        if (!apple_modern_kc_ignition_compat(bootkc,
                                             s->blobs[ASSET_BOOTKC].size,
                                             &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in img4-ignition-compat patch "
                    "to the in-memory kernel cache (compatibility, not Apple "
                    "fidelity)");
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
    if (s->boot_display && !apple_modern_boot_display_create(
            &s->ram, s->metadata.layout.framebuffer_physical -
                     s->components.dram_base,
            s->display_width, s->display_height,
            s->display_stride ? s->display_stride : s->display_width * 4,
            serial_hd(0), &error)) {
        error_report_err(error);
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < s->board_regions.count; i++) {
        AppleModernBoardRegion *r = &s->board_regions.windows[i];
        memory_region_init_ram(&s->cpu_register_ram[i], NULL, r->name,
                               r->size, &error_fatal);
        memory_region_add_subregion(get_system_memory(), r->physical_address,
                                    &s->cpu_register_ram[i]);
    }
    if (!map_amcc(s, &error) || !map_aic(s, &error) || !map_sep(s, &error) ||
        (s->sep_trace && !map_sep_trace(s, &error))) {
        error_report_err(error);
        exit(EXIT_FAILURE);
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
    object_property_set_bool(OBJECT(s->cpu), "apple-modern-apsts", true,
                              &error_fatal);
    if (s->pauth_compat) {
        object_property_set_bool(OBJECT(s->cpu), "apple-modern-pauth-compat",
                                 true, &error_fatal);
        warn_report("apple-modern: pointer authentication sign/authenticate "
                    "are no-ops (opt-in pauth-compat; compatibility, not "
                    "Apple fidelity)");
    }
    object_property_set_bool(OBJECT(s->cpu), "apple-modern-sysregs", true,
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
    /*
     * As in Darwin-VM: limit SME streaming vector lengths to 128/256/512
     * bits. With QEMU's max (2048-bit) SVL, XNU's per-thread ZA save area
     * exceeds its zone element limit ("zone_create: element size too large:
     * 74328") and the kernel panics during early zone setup.
     */
    s->cpu->sme_vq.supported = 0x0b;
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
BOOL_PROPERTY(img4_ignition_compat, img4_ignition_compat)
BOOL_PROPERTY(pauth_compat, pauth_compat)
BOOL_PROPERTY(sep_trace, sep_trace)
BOOL_PROPERTY(boot_display, boot_display)
BOOL_PROPERTY(prepare_only, prepare_only)
BOOL_PROPERTY(mte, mte)
#undef BOOL_PROPERTY

static void get_display_geometry(Object *obj, Visitor *visitor, const char *name,
                                 void *opaque, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    size_t offset = (size_t)opaque;
    uint32_t *field = (uint32_t *)((uint8_t *)s + offset);
    uint32_t value = *field;

    visit_type_uint32(visitor, name, &value, errp);
}

static void set_display_geometry(Object *obj, Visitor *visitor, const char *name,
                                 void *opaque, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    size_t offset = (size_t)opaque;
    uint32_t *field = (uint32_t *)((uint8_t *)s + offset);
    uint32_t value;

    if (check_mutable(s, errp) && visit_type_uint32(visitor, name, &value, errp)) {
        *field = value; /* Cross-field bounds are validated by the layout. */
    }
}

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
    s->display_width = 1024;
    s->display_height = 768;
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
    mc->desc = "Modern Apple boot experiment (optional boot framebuffer)";
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
    object_class_property_add_bool(oc, "pauth-compat", get_pauth_compat,
                                   set_pauth_compat);
    object_class_property_add_bool(oc, "sep-trace", get_sep_trace,
                                   set_sep_trace);
    object_class_property_add_bool(oc, "img4-ignition-compat",
                                   get_img4_ignition_compat,
                                   set_img4_ignition_compat);
    object_class_property_add_bool(oc, "prepare-only", get_prepare_only, set_prepare_only);
    object_class_property_add_bool(oc, "boot-display", get_boot_display,
                                   set_boot_display);
    object_class_property_add(oc, "boot-display-width", "uint32",
                              get_display_geometry, set_display_geometry,
                              NULL, (void *)offsetof(AppleModernMachine,
                                                     display_width));
    object_class_property_add(oc, "boot-display-height", "uint32",
                              get_display_geometry, set_display_geometry,
                              NULL, (void *)offsetof(AppleModernMachine,
                                                     display_height));
    object_class_property_add(oc, "boot-display-stride", "uint32",
                              get_display_geometry, set_display_geometry,
                              NULL, (void *)offsetof(AppleModernMachine,
                                                     display_stride));
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
