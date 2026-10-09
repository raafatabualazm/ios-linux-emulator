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
#include "hw/arm/apple-silicon/modern-pmgr.h"
#include "hw/arm/apple-silicon/modern-pmgr-fuse.h"
#include "hw/arm/apple-silicon/modern-mcc-dramcfg.h"
#include "hw/arm/apple-silicon/modern-mcc-quota.h"
#include "hw/arm/apple-silicon/modern-mcc-perf.h"
#include "hw/arm/apple-silicon/modern-mcc-socni.h"
#include "hw/arm/apple-silicon/modern-mcc-socni-command.h"
#include "hw/arm/apple-silicon/modern-mcc-dcs-perf.h"
#include "hw/arm/apple-silicon/modern-pmgr-voltage.h"
#include "hw/arm/apple-silicon/modern-pmp-ptd.h"
#include "hw/arm/apple-silicon/modern-cpu-dvfm.h"
#include "hw/arm/apple-silicon/modern-pmgr-storage.h"
#include "hw/arm/apple-silicon/modern-mcc-dsid.h"
#include "hw/arm/apple-silicon/modern-mcc-slc.h"
#include "hw/arm/apple-silicon/modern-kc-patch.h"
#include "hw/intc/apple-modern-aic.h"
#include "hw/arm/apple-silicon/sep-sim.h"
#include "hw/arm/apple-silicon/dart-t8110.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/qdev-properties.h"
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
    bool sep_mailbox;
    bool sep_sim;
    bool sep_dart;
    bool modern_pmgr;
    bool modern_mcc_dramcfg;
    uint32_t mcc_dramcfg_reset;
    AppleModernMCCDRAMCFGPlan mcc_dramcfg_plan;
    bool modern_mcc_quota;
    uint32_t mcc_quota_reset;
    AppleModernMCCQuotaPlan mcc_quota_plan;
    bool modern_mcc_perf;
    uint64_t mcc_perf_reset;
    AppleModernMCCPerfPlan mcc_perf_plan;
    bool modern_mcc_socni;
    uint64_t mcc_socni_reset;
    AppleModernMCCSocniPlan mcc_socni_plan;
    bool modern_mcc_socni_command;
    AppleModernMCCSocniCommandPlan mcc_socni_command_plan;
    bool modern_mcc_dcs_perf;
    uint64_t mcc_dcs_perf_reset;
    AppleModernDCSPERFPlan mcc_dcs_perf_plan;
    bool modern_mcc_dsid;
    uint64_t mcc_dsid_reset;
    AppleModernMCCDSIDPlan mcc_dsid_plan;
    bool modern_mcc_slc;
    AppleModernMCCSLCPlan mcc_slc_plan;
    char *pmgr_aon_fuse_image;
    /* Declared profile for the iBoot-computed /arm-io/pmgr voltage-states*. */
    char *pmgr_voltage_states;
    bool modern_pmp_ptd;
    AppleModernPTDPlan pmp_ptd_plan;
    bool modern_cpu_dvfm;
    AppleModernDVFMPlan cpu_dvfm_plan;
    /* Declared storage for the PMGR perf-counter registers ApplePMGR programs. */
    bool modern_pmgr_storage;
    AppleModernPMGRStoragePlan pmgr_storage_plan;
    /* Declared reset profile naming PMGR domains iBoot leaves powered on. */
    char *pmgr_boot_on;
    /* Publish the modelled counter frequency as /cpus/cpu0 timebase-frequency. */
    bool adt_timebase_match;
    AppleModernPMGRFusePlan pmgr_fuse_plan;
    AppleDARTT8110State *sep_mapper;
    AddressSpace *sep_dma_as;
    DeviceState *sep_mbox;
    bool aic_trace;
    bool modern_aic;
    DeviceState *aic;
    uint32_t uart_irq;
    uint32_t aic_num_irqs;
    uint32_t aic_revision;
    /*
     * Published as /arm-io/aic "aic-iack-offset" and used as the controller's
     * acknowledge offset, so the served tree and the model cannot disagree.
     */
    uint32_t aic_iack_offset;
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
                   "most 512 MiB within the %zu-byte caller budget: %s",
                   budget, path);
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
                         uint64_t *span, uint32_t *irq, Error **errp)
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
    if (irq) {
        AppleModernBlob interrupts;
        Error *local = NULL;

        *irq = UINT32_MAX;
        if (apple_modern_adt_property(dtree, "/arm-io/uart0", "interrupts",
                                      &interrupts, &local)) {
            if (interrupts.size >= 4) {
                *irq = ldl_le_p(interrupts.data);
            }
        } else {
            error_free(local);
        }
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

static bool append_pmgr_exclusion(AppleModernAddressRange *exclusions,
    size_t *count, AppleModernAddressRange range, Error **errp)
{
    if (*count >= APPLE_MODERN_MAX_BOARD_EXCLUSIONS) {
        error_setg(errp, "modern register exclusion budget exceeded");
        return false;
    }
    exclusions[(*count)++] = range;
    return true;
}

/* Power-state cells only: preserving the tree does not supply MCC or DVFS. */
static bool pmgr_exclusions(AppleModernMachine *s, uint64_t uart,
    uint64_t uart_span, AppleModernAddressRange *exclusions,
    size_t *output_count, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    size_t count = 0;
    static const char *const paths[] = {
        "/arm-io/aic", "/arm-io/sep", "/arm-io/dart-sep",
    };
    bool mapped[] = {true, s->sep_trace || s->sep_mailbox || s->sep_sim,
                     s->sep_dart};

    if (!append_pmgr_exclusion(exclusions, &count,
            (AppleModernAddressRange){uart, uart_span}, errp)) {
        return false;
    }
    for (size_t i = 0; i < s->board_regions.count; i++) {
        AppleModernBoardRegion *r = &s->board_regions.windows[i];
        if (!append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){r->physical_address, r->size}, errp)) {
            return false;
        }
    }
    if (s->has_amcc) {
        if (!append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->amcc.base, s->amcc.size}, errp)) {
            return false;
        }
    }
    for (size_t i = 0; i < ARRAY_SIZE(paths); i++) {
        AppleModernBlob reg;
        if (!mapped[i]) {
            continue;
        }
        if (!apple_modern_adt_property(dtree, paths[i], "reg", &reg, errp)) {
            return false;
        }
        if (!reg.size || reg.size % 16 || reg.size > 4 * 16) {
            error_setg(errp, "invalid %s PMGR exclusion geometry", paths[i]);
            return false;
        }
        for (size_t j = 0; j < reg.size; j += 16) {
            uint64_t base, size = ldq_le_p(reg.data + j + 8);
            if (!arm_io_translate(dtree, ldq_le_p(reg.data + j), size,
                                   &base, errp)) {
                return false;
            }
            if (!append_pmgr_exclusion(exclusions, &count,
                    (AppleModernAddressRange){base, size}, errp)) {
                return false;
            }
        }
    }
    AppleModernBlob hmac;
    if (apple_modern_adt_property(dtree,
            "/arm-io/sep/iop-sep-nub/InvalidateHmac", "reg-block", &hmac, NULL)) {
        if (hmac.size != 16) {
            error_setg(errp, "invalid SEP reg-block PMGR exclusion");
            return false;
        }
        if (!append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){ldq_le_p(hmac.data),
                                         ldq_le_p(hmac.data + 8)}, errp)) {
            return false;
        }
    }
    /* Every append is bounded; the full declared profile uses at most 68 spans. */
    for (unsigned i = 0; i < APPLE_MODERN_MCC_DCS_COUNT; i++) {
        if (s->mcc_dramcfg_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->mcc_dramcfg_plan.addresses[i], 4}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_MCC_QUOTA_VIEWS; i++) {
        if (s->mcc_quota_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->mcc_quota_plan.addresses[i],
                                        APPLE_MODERN_MCC_QUOTA_SPAN}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_MCC_PERF_VIEWS; i++) {
        if (s->mcc_perf_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->mcc_perf_plan.addresses[i],
                    i % 2 ? APPLE_MODERN_MCC_PERF_COUNTER_SPAN : 8}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SOCNI_VIEWS; i++) {
        if (s->mcc_socni_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->mcc_socni_plan.addresses[i],
                                         s->mcc_socni_plan.spans[i]}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS; i++) {
        if (s->mcc_socni_command_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->mcc_socni_command_plan.addresses[i],
                                         APPLE_MODERN_MCC_SOCNI_COMMAND_SPAN},
                errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_DCS_PERF_VIEWS; i++) {
        if (s->mcc_dcs_perf_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->mcc_dcs_perf_plan.addresses[i],
                                         s->mcc_dcs_perf_plan.spans[i]}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_MCC_DSID_VIEWS; i++) {
        if (s->mcc_dsid_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->mcc_dsid_plan.addresses[i],
                                         s->mcc_dsid_plan.spans[i]}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SLC_VIEWS; i++) {
        if (s->mcc_slc_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->mcc_slc_plan.addresses[i],
                                         APPLE_MODERN_MCC_SLC_SPAN}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_PTD_VIEWS; i++) {
        if (s->pmp_ptd_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->pmp_ptd_plan.addresses[i],
                                         APPLE_MODERN_PTD_SPAN}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_DVFM_WINDOWS; i++) {
        if (s->cpu_dvfm_plan.addresses[i] &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->cpu_dvfm_plan.addresses[i],
                                         APPLE_MODERN_DVFM_SPAN}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < s->pmgr_storage_plan.count; i++) {
        if (!append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->pmgr_storage_plan.windows[i].address,
                                         s->pmgr_storage_plan.windows[i].size},
                errp)) {
            return false;
        }
    }
    if (s->pmgr_fuse_plan.size &&
        !append_pmgr_exclusion(exclusions, &count,
            (AppleModernAddressRange){s->pmgr_fuse_plan.base,
                                     s->pmgr_fuse_plan.size}, errp)) {
        return false;
    }
    *output_count = count;
    return true;
}

static bool map_mcc_dramcfg(AppleModernMachine *s, uint64_t uart,
                            uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernMCCDRAMCFGPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_mcc_dramcfg_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_mcc_dramcfg_new(s->mcc_dramcfg_reset);
    dev->id = g_strdup("mcc-dramcfg");
    object_property_add_child(OBJECT(s), "mcc-dramcfg", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_DCS_COUNT; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->mcc_dramcfg_plan = plan;
    warn_report("apple-modern: opt-in four sparse MCC DRAM configuration words; "
                "declared virtual reset 0x%08x, no DRAM timing/cache-way model",
                s->mcc_dramcfg_reset);
    return true;
}

static bool map_pmgr(AppleModernMachine *s, uint64_t uart, uint64_t uart_span,
                       Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernPMGRPlan plan;
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_pmgr_plan_build(dtree, s->components.dram_base,
                                      s->components.dram_size, exclusions,
                                      count, &plan, errp)) {
        return false;
    }
    if (s->pmgr_boot_on) {
        size_t names_count;
        const char *const *names = apple_modern_pmgr_boot_on_profile(
            s->pmgr_boot_on, &names_count);
        if (!names) {
            error_setg(errp, "unknown pmgr-boot-on profile '%s' (supported: j700)",
                       s->pmgr_boot_on);
            return false;
        }
        if (!apple_modern_pmgr_plan_set_boot_on(dtree, &plan, names, names_count,
                                                errp)) {
            return false;
        }
        warn_report("apple-modern: %zu PMGR domains reset powered on from the "
                    "'%s' profile (Asahi T8140 always-on set; analogy for "
                    "iPhone17,3, not an attested handover state)", names_count,
                    s->pmgr_boot_on);
    }
    DeviceState *dev = apple_modern_pmgr_new(&plan);
    dev->id = g_strdup("modern-pmgr");
    object_property_add_child(OBJECT(s), "pmgr", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < plan.window_count; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.windows[i].base);
    }
    warn_report("apple-modern: opt-in PMGR power cells: %u windows, %u cells, "
                "%u virtual domains; no MCC, DVFS, PMP or PMGR IRQ model",
                plan.window_count, plan.cell_count, plan.virtual_count);
    return true;
}

static bool map_mcc_quota(AppleModernMachine *s, uint64_t uart,
                          uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernMCCQuotaPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_mcc_quota_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_mcc_quota_new(s->mcc_quota_reset);
    dev->id = g_strdup("mcc-quota");
    object_property_add_child(OBJECT(s), "mcc-quota", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_QUOTA_VIEWS; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->mcc_quota_plan = plan;
    warn_report("apple-modern: opt-in sparse DSID quota storage; "
                "declared virtual reset 0x%08x and global broadcast propagation",
                s->mcc_quota_reset);
    return true;
}

static bool map_mcc_perf(AppleModernMachine *s, uint64_t uart,
                          uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernMCCPerfPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_mcc_perf_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_mcc_perf_new(s->mcc_perf_reset);
    dev->id = g_strdup("mcc-perf");
    object_property_add_child(OBJECT(s), "mcc-perf", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_PERF_VIEWS; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->mcc_perf_plan = plan;
    warn_report("apple-modern: opt-in sparse AMCC performance channels; "
                "virtual reset 0x%016" PRIx64 "; no bus/cache event source connected",
                s->mcc_perf_reset);
    return true;
}

static bool map_mcc_socni(AppleModernMachine *s, uint64_t uart,
                          uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernMCCSocniPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_mcc_socni_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_mcc_socni_new(s->mcc_socni_reset);
    dev->id = g_strdup("mcc-socni");
    object_property_add_child(OBJECT(s), "mcc-socni", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SOCNI_VIEWS; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->mcc_socni_plan = plan;
    warn_report("apple-modern: opt-in sparse SOCNI performance channels; "
                "virtual reset 0x%016" PRIx64 "; no bus/cache event source connected",
                s->mcc_socni_reset);
    return true;
}

static bool map_mcc_socni_command(AppleModernMachine *s, uint64_t uart,
                                  uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernMCCSocniCommandPlan plan;
    size_t count;
    if (!s->modern_mcc_socni) {
        error_setg(errp, "modern-mcc-socni-command requires modern-mcc-socni");
        return false;
    }
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_mcc_socni_command_plan_build(dtree,
            s->components.dram_base, s->components.dram_size,
            exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *channels = DEVICE(object_property_get_link(OBJECT(s),
                                           "mcc-socni", &error_abort));
    DeviceState *dev = apple_modern_mcc_socni_command_new(channels);
    dev->id = g_strdup("mcc-socni-command");
    object_property_add_child(OBJECT(s), "mcc-socni-command", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->mcc_socni_command_plan = plan;
    warn_report("apple-modern: SOCNI command uses declared bank-arm semantics; "
                "no physical event source or cache/power readiness is supplied");
    return true;
}

static bool map_mcc_dcs_perf(AppleModernMachine *s, uint64_t uart,
                             uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernDCSPERFPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_dcs_perf_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_dcs_perf_new(s->mcc_dcs_perf_reset);
    dev->id = g_strdup("mcc-dcs-perf");
    object_property_add_child(OBJECT(s), "mcc-dcs-perf", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_DCS_PERF_VIEWS; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->mcc_dcs_perf_plan = plan;
    warn_report("apple-modern: opt-in sparse DCS performance block on DCS0-2; "
                "declared profile: virtual reset 0x%016" PRIx64 " (all counters), "
                "clear bits complete at once and zero their duration counter, "
                "counter stores abort; no DRAM event source connected",
                s->mcc_dcs_perf_reset);
    return true;
}

static bool map_mcc_dsid(AppleModernMachine *s, uint64_t uart,
                         uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernMCCDSIDPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_mcc_dsid_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_mcc_dsid_new(s->mcc_dsid_reset);
    dev->id = g_strdup("mcc-dsid");
    object_property_add_child(OBJECT(s), "mcc-dsid", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_DSID_VIEWS; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->mcc_dsid_plan = plan;
    warn_report("apple-modern: opt-in sparse AMCC DSID profile cells; counter "
                "virtual reset 0x%016" PRIx64 "; no DSID event source connected",
                s->mcc_dsid_reset);
    return true;
}

/* Darwin's compatibility AMCC aperture reads zero across plane 0's SLC
 * status cells, which the driver polls without a bound. Replace its
 * exclusion with the aperture minus exactly the SLC views that lie inside
 * it. A view straddling its edge, or overlapping its lock word at offset 0
 * or a CTRR bound register, fails, so those stay with the aperture. */
static bool carve_amcc_aperture(AppleModernMachine *s,
    const AppleModernMCCSLCPlan *plan, AppleModernAddressRange *exclusions,
    size_t *count, Error **errp)
{
    uint64_t base = s->amcc.base, end = s->amcc.base + s->amcc.size;
    uint64_t cells[APPLE_MODERN_MCC_SLC_VIEWS];
    size_t inside = 0;
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SLC_VIEWS; i++) {
        uint64_t cell = plan->addresses[i];
        if (cell + APPLE_MODERN_MCC_SLC_SPAN <= base || cell >= end) {
            continue;
        }
        if (cell < base || cell + APPLE_MODERN_MCC_SLC_SPAN > end) {
            error_setg(errp, "MCC SLC view straddles the compatibility AMCC aperture");
            return false;
        }
        for (unsigned b = 0; b <= APPLE_MODERN_AMCC_BANKS; b++) {
            /* Bank index APPLE_MODERN_AMCC_BANKS stands for offset 0. */
            for (unsigned r = 0; r < 2; r++) {
                uint32_t reg = b == APPLE_MODERN_AMCC_BANKS ? 0 :
                               r ? s->amcc.upr_reg[b] : s->amcc.lwr_reg[b];
                if ((reg || b == APPLE_MODERN_AMCC_BANKS) &&
                    cell < base + reg + 8 && base + reg < cell + APPLE_MODERN_MCC_SLC_SPAN) {
                    error_setg(errp, "MCC SLC view overlaps a compatibility AMCC "
                               "lock or CTRR bound register");
                    return false;
                }
            }
        }
        /* Views are planned in plane order; keep the list ascending. */
        size_t j = inside++;
        for (; j && cells[j - 1] > cell; j--) {
            cells[j] = cells[j - 1];
        }
        cells[j] = cell;
    }
    for (size_t c = 0; c <= inside; c++) {
        uint64_t stop = c < inside ? cells[c] : end;
        if (stop > base && !append_pmgr_exclusion(exclusions, count,
                (AppleModernAddressRange){base, stop - base}, errp)) {
            return false;
        }
        base = stop + APPLE_MODERN_MCC_SLC_SPAN;
    }
    return true;
}

static bool map_mcc_slc(AppleModernMachine *s, uint64_t uart,
                        uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernMCCSLCPlan plan;
    size_t count;
    bool carved = false;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp)) {
        return false;
    }
    for (size_t i = 0; s->has_amcc && i < count; i++) {
        if (exclusions[i].physical_address == s->amcc.base &&
            exclusions[i].size == s->amcc.size) {
            exclusions[i] = exclusions[--count];
            carved = true;
            break;
        }
    }
    if (s->has_amcc && !carved) {
        error_setg(errp, "MCC SLC cannot find the compatibility AMCC exclusion");
        return false;
    }
    /* Plan against every other device first, then re-check the views
     * against what remains of the aperture after the carve. */
    if (!apple_modern_mcc_slc_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp) ||
        (carved && (!carve_amcc_aperture(s, &plan, exclusions, &count, errp) ||
                    !apple_modern_mcc_slc_plan_build(dtree, s->components.dram_base,
                        s->components.dram_size, exclusions, count, &plan, errp)))) {
        return false;
    }
    DeviceState *dev = apple_modern_mcc_slc_new();
    dev->id = g_strdup("mcc-slc");
    object_property_add_child(OBJECT(s), "mcc-slc", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SLC_VIEWS; i++) {
        uint64_t cell = plan.addresses[i];
        if (carved && cell >= s->amcc.base && cell < s->amcc.base + s->amcc.size) {
            /* Above the compatibility aperture, which is mapped at priority 0. */
            sysbus_mmio_map_overlap(SYS_BUS_DEVICE(dev), i, cell, 1);
        } else {
            sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, cell);
        }
    }
    s->mcc_slc_plan = plan;
    warn_report("apple-modern: opt-in AMCC SLC way/flush cells; declared profile: "
                "12-way handover state (per-plane readback on t604x/t8140-family "
                "Macs, m1n1 PR #664, analogy), "
                "global writes broadcast and requested ways report powered at once; "
                "no cache model");
    return true;
}

static bool map_pmp_ptd(AppleModernMachine *s, uint64_t uart,
                        uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernPTDPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_pmp_ptd_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_pmp_ptd_new();
    dev->id = g_strdup("pmp-ptd");
    object_property_add_child(OBJECT(s), "pmp-ptd", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_PTD_VIEWS; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->pmp_ptd_plan = plan;
    warn_report("apple-modern: opt-in PMP PTD message board (MCC reg[6] Dashboard, "
                "reg[7] Update); Update stores mirror into the Dashboard "
                "(declared); no PMP responder: no acknowledgement or response "
                "is ever produced");
    return true;
}

static bool map_cpu_dvfm(AppleModernMachine *s, uint64_t uart,
                         uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernDVFMPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_cpu_dvfm_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_cpu_dvfm_new();
    dev->id = g_strdup("cpu-dvfm");
    object_property_add_child(OBJECT(s), "cpu-dvfm", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < APPLE_MODERN_DVFM_WINDOWS; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.addresses[i]);
    }
    s->cpu_dvfm_plan = plan;
    warn_report("apple-modern: opt-in CPU DVFM windows (state tables E 0x%" PRIx64
                ", P 0x%" PRIx64 "; control pages E 0x%" PRIx64 ", P 0x%" PRIx64
                "); declared zero-reset storage, NOT calibration data (a "
                "boot-progress diagnostic profile)",
                plan.addresses[0], plan.addresses[1], plan.addresses[2],
                plan.addresses[3]);
    return true;
}

static bool map_pmgr_storage(AppleModernMachine *s, uint64_t uart,
                             uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernPMGRStoragePlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_pmgr_storage_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_pmgr_storage_new(&plan);
    dev->id = g_strdup("pmgr-storage");
    object_property_add_child(OBJECT(s), "pmgr-storage", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < plan.count; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), i, plan.windows[i].address);
    }
    s->pmgr_storage_plan = plan;
    warn_report("apple-modern: opt-in PMGR perf-counter register storage (%u windows, "
                "%u 32-bit registers derived from the ADT perf-groups/perf-counters); "
                "declared zero-reset storage, NOT calibration data and no counting "
                "behaviour (a boot-progress diagnostic profile)",
                plan.count, plan.registers);
    return true;
}

static bool map_pmgr_fuse(AppleModernMachine *s, uint64_t uart,
                           uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernBlob image = {0};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernPMGRFusePlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_pmgr_fuse_plan_build(dtree, s->components.dram_base,
                s->components.dram_size, exclusions, count, &plan, errp) ||
        !read_asset(s->pmgr_aon_fuse_image, &image,
                     APPLE_MODERN_PMGR_FUSE_SIZE, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_pmgr_fuse_new(image, errp);
    g_free((void *)image.data);
    if (!dev) {
        return false;
    }
    dev->id = g_strdup("pmgr-fuse");
    object_property_add_child(OBJECT(s), "pmgr-fuse", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, plan.base);
    s->pmgr_fuse_plan = plan;
    warn_report("apple-modern: PMGR_AON_FUSE uses an explicit immutable input; "
                "its authenticity and hardware calibration are not established");
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
 * Observation aperture for the AIC window. Opt-in (aic-trace), default off.
 * It answers exactly the three capability registers the RAM stub answers today
 * (revision at rev-offset 0, cap0 at 0x4, IRQ count at maxnumirq-offset 0xc)
 * so driver initialization is unchanged, returns zero elsewhere, discards
 * writes, and logs every access under -d unimp. The stock ADT describes the
 * offsets and the 0x4a00 per-die stride but names no event/acknowledge
 * register, so that location is measured here rather than inferred.
 */
typedef struct AppleModernAICTrace {
    uint64_t base;
    uint32_t num_irqs;
} AppleModernAICTrace;

static uint64_t aic_trace_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleModernAICTrace *t = opaque;
    uint64_t value = 0;

    if (offset == 0xc || offset == 0x4) {
        value = t->num_irqs;
    }
    qemu_log_mask(LOG_UNIMP, "AIC-TRACE read  +0x%06" PRIx64 " size %u -> 0x%"
                  PRIx64 "\n", (uint64_t)offset, size, value);
    return value;
}

static void aic_trace_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "AIC-TRACE write +0x%06" PRIx64 " size %u value "
                  "0x%" PRIx64 "\n", (uint64_t)offset, size, value);
}

static const MemoryRegionOps aic_trace_ops = {
    .read = aic_trace_read,
    .write = aic_trace_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

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
    if (s->modern_aic) {
        /*
         * Geometry comes from the served ADT. The bank layout is the Asahi
         * reference one and is corroborated by this tree: 4096 IRQ config
         * words (0x4000) plus five 0x200 bitmap banks (0xa00) equals the
         * stock extintrcfg/intmaskset/intmaskclear/hwintmon stride of 0x4a00.
         * The measured guest driver masks at irq_config + 0x4400 and unmasks
         * at + 0x4688, which is exactly this layout's MASK_SET/MASK_CLEAR.
         * The acknowledge offset IS named by the ADT, as aic-iack-offset,
         * and it is the only thing XNU reads for it: the driver defaults that
         * member to zero and panics at AppleInterruptControllerV3.cpp:214
         * when it is still zero. We publish the property ourselves (see
         * metadata_input.aic_iack_offset) and read it back here, so the tree
         * the guest parses and the offset we decode are the same number.
         * The value remains our declared choice: Apple documents none, and
         * the reference project's 0x1000 cannot be right because that is
         * Apple's own pubstampcfg0-offset, which this same driver both reads
         * and writes.
         */
        /*
         * The ADT compatible is "aic,3". The revision register value selects
         * the driver's internal path: reporting 3 makes XNU read the unnamed
         * CPU register S3_3_C15_C2_0, which no reference models. aic-revision
         * exists to measure that boundary; it is a declared compatibility
         * interface, not a claim about silicon.
         */
        const uint32_t revision = s->aic_revision;
        uint32_t extint = 0, stamp_off = 0, stamp_count = 0, stamp_stride = 0;
        uint32_t rev_off = APPLE_MODERN_AIC_VERSION_OFFSET;
        uint32_t glbcfg_off = APPLE_MODERN_AIC_CONFIG_OFFSET;
        uint32_t cap0_off = 4, maxnumirq_off = 0xc, extint_num = 0;
        AppleModernBlob iack;

        if (!adt_u32(dtree, "/arm-io/aic", "extint-baseaddress", &extint,
                     errp)) {
            return false;
        }
        /*
         * Prefer the ADT for every offset XNU itself reads, keeping the
         * measured values as fallbacks. They agree on this part (rev 0x0,
         * cap0 0x4, maxnumirq 0xc, aicglbcfg 0x14) and the driver carries the
         * same compiled-in defaults, so this is defensive rather than a fix:
         * a different part that moved them would otherwise diverge silently.
         */
        adt_u32(dtree, "/arm-io/aic", "rev-offset", &rev_off, NULL);
        adt_u32(dtree, "/arm-io/aic", "cap0-offset", &cap0_off, NULL);
        adt_u32(dtree, "/arm-io/aic", "maxnumirq-offset", &maxnumirq_off, NULL);
        adt_u32(dtree, "/arm-io/aic", "aicglbcfg-offset", &glbcfg_off, NULL);
        /*
         * max-extint-num selects which mask banks XNU uses: its driver does
         * csel on this property and moves mask-set/mask-clear/hwintmon to
         * extint_base + 0x8800/0x8c00/0x9000 when it is nonzero. Our banks
         * follow the zero branch, so refuse rather than mismatch in silence.
         * The property is absent from every tree measured so far.
         */
        if (adt_u32(dtree, "/arm-io/aic", "max-extint-num", &extint_num,
                    NULL) && extint_num) {
            error_setg(errp, "modern AIC ADT sets max-extint-num %u; the "
                       "modelled mask banks only match the zero branch",
                       extint_num);
            return false;
        }
        /*
         * The acknowledge offset comes from the property we published, so the
         * guest and the model necessarily agree. XNU rejects any length other
         * than eight (AppleInterruptControllerV3.cpp:195).
         */
        if (!apple_modern_adt_property(dtree, "/arm-io/aic",
                                       "aic-iack-offset", &iack, errp)) {
            return false;
        }
        if (iack.size != 8 || ldq_le_p(iack.data) != s->aic_iack_offset) {
            error_setg(errp, "served aic-iack-offset does not match the "
                       "modelled acknowledge offset 0x%x", s->aic_iack_offset);
            return false;
        }
        s->aic = qdev_new(TYPE_APPLE_MODERN_AIC);
        qdev_prop_set_uint32(s->aic, "revision", revision);
        qdev_prop_set_uint32(s->aic, "num-irqs", num_irqs);
        qdev_prop_set_uint32(s->aic, "max-irqs", num_irqs);
        qdev_prop_set_uint32(s->aic, "version-offset", rev_off);
        qdev_prop_set_uint32(s->aic, "config-offset", glbcfg_off);
        qdev_prop_set_uint32(s->aic, "cap0-offset", cap0_off);
        qdev_prop_set_uint32(s->aic, "maxnumirq-offset", maxnumirq_off);
        qdev_prop_set_uint32(s->aic, "irq-config-offset", extint);
        qdev_prop_set_uint32(s->aic, "event-offset", s->aic_iack_offset);
        /*
         * Shared timestamp block: ADT pubstampcfg0-offset with
         * #shared-timestamps entries of pubstampstride-mask bytes. Accepted
         * and discarded; the counters themselves are not modelled.
         */
        if (adt_u32(dtree, "/arm-io/aic", "pubstampcfg0-offset", &stamp_off,
                    NULL) &&
            adt_u32(dtree, "/arm-io/aic", "#shared-timestamps", &stamp_count,
                    NULL) &&
            adt_u32(dtree, "/arm-io/aic", "pubstampstride-mask", &stamp_stride,
                    NULL) && stamp_count && stamp_stride &&
            stamp_count <= 256 && stamp_stride <= 0x100) {
            qdev_prop_set_uint32(s->aic, "timestamp-offset", stamp_off);
            qdev_prop_set_uint32(s->aic, "timestamp-size",
                                 stamp_count * stamp_stride);
        }
        qdev_prop_set_uint32(s->aic, "mmio-size", size);
        qdev_prop_set_bit(s->aic, "trace", s->aic_trace);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(s->aic), &error_fatal);
        sysbus_mmio_map(SYS_BUS_DEVICE(s->aic), 0, base);
        s->aic_num_irqs = num_irqs;
        warn_report("apple-modern: AIC%u enabled, %u IRQs, config at 0x%x "
                    "(opt-in modern-aic)", revision, num_irqs, extint);
        return true;
    }
    if (s->aic_trace) {
        AppleModernAICTrace *trace = g_new0(AppleModernAICTrace, 1);

        trace->base = base;
        trace->num_irqs = num_irqs;
        memory_region_init_io(&s->aic_ram, NULL, &aic_trace_ops, trace,
                              "apple-modern.aic-trace", size);
        memory_region_add_subregion(get_system_memory(), base, &s->aic_ram);
        warn_report("apple-modern: AIC trace aperture at 0x%" PRIx64 " size 0x%"
                    PRIx64 " (observation only, not a controller)", base, size);
        return true;
    }
    memory_region_init_ram(&s->aic_ram, NULL, "apple-modern.aic", size,
                           &error_fatal);
    memory_region_add_subregion(get_system_memory(), base, &s->aic_ram);
    cpu_physical_memory_write(base + 0xC, &num_irqs, sizeof(num_irqs));
    return true;
}

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

/*
 * Normal SEP IOVA provider, opt-in and separate from mailbox/sepOS semantics.
 * Both iommu-parent phandles are preserved and resolved, not treated as SIDs.
 * The prepared d47ap ADT describes one t8110 DART and its two mapper nubs.
 * Legacy apple-dart has a different register ABI and is deliberately untouched.
 */
static bool map_sep_dart(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob reg, ints, value, parents;
    uint64_t base, offset, span;
    uint32_t num_streams, streams[2], mapper_phandles[2];
    static const char *mapper_paths[] = {
        "/arm-io/dart-sep/mapper-sep",
        "/arm-io/dart-sep/mapper-sep-mpm",
    };

    if (!s->aic) {
        error_setg(errp, "sep-dart requires modern-aic for DMA fault delivery");
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-sep", "reg",
                                   &reg, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/dart-sep", "interrupts",
                                   &ints, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/sep", "iommu-parent",
                                   &parents, errp)) {
        return false;
    }
    if (reg.size != 16 || ints.size != 4 || parents.size != 8) {
        error_setg(errp, "unsupported SEP DART reg/IRQ/mapper schema");
        return false;
    }
    offset = ldq_le_p(reg.data);
    span = ldq_le_p(reg.data + 8);
    if (span < 0x1800 || span > 0x400000 ||
        ldl_le_p(ints.data) >= s->aic_num_irqs ||
        !arm_io_translate(dtree, offset, span, &base, errp)) {
        if (!errp || !*errp) {
            error_setg(errp, "modern SEP DART geometry exceeds supported bounds");
        }
        return false;
    }
    if (apple_modern_adt_property(dtree, "/arm-io/dart-sep", "compatible",
                                  &value, NULL) &&
        (value.size < sizeof("dart,t8110") ||
         memcmp(value.data, "dart,t8110", sizeof("dart,t8110")))) {
        error_setg(errp, "modern SEP DART requires dart,t8110 compatible");
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-sep", "page-size",
                                   &value, errp)) {
        return false;
    }
    if (value.size != 4 || ldl_le_p(value.data) != 0x4000) {
        error_setg(errp, "modern SEP DART supports only 16 KiB pages");
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-sep", "sid-count",
                                   &value, errp)) {
        return false;
    }
    if (value.size != 4 || !(num_streams = ldl_le_p(value.data)) ||
        num_streams > APPLE_DART_T8110_STREAMS) {
        error_setg(errp, "modern SEP DART sid-count is out of range");
        return false;
    }
    for (unsigned i = 0; i < ARRAY_SIZE(mapper_paths); i++) {
        if (!apple_modern_adt_property(dtree, mapper_paths[i], "AAPL,phandle",
                                       &value, errp)) {
            return false;
        }
        if (value.size != 4) {
            error_setg(errp, "modern SEP DART mapper phandle must be u32");
            return false;
        }
        mapper_phandles[i] = ldl_le_p(value.data);
        if (!apple_modern_adt_property(dtree, mapper_paths[i], "reg",
                                       &value, errp)) {
            return false;
        }
        if (value.size != 4 ||
            (streams[i] = ldl_le_p(value.data)) >= num_streams ||
            ldl_le_p(parents.data + i * 4) != mapper_phandles[i]) {
            error_setg(errp, "modern SEP iommu-parent must resolve to the two "
                       "dart-sep mapper nubs with in-range streams");
            return false;
        }
    }
    if (streams[0] == streams[1] || mapper_phandles[0] == mapper_phandles[1]) {
        error_setg(errp, "modern SEP DART mapper nubs must be distinct");
        return false;
    }

    DeviceState *dev = qdev_new(TYPE_APPLE_DART_T8110);
    s->sep_mapper = APPLE_DART_T8110(dev);
    dev->id = g_strdup("modern-sep-dart");
    object_property_add_child(OBJECT(s), "dart-sep", OBJECT(dev));
    qdev_prop_set_uint32(dev, "mmio-size", span);
    qdev_prop_set_uint32(dev, "num-streams", num_streams);
    /* 42-bit VA covers the ADT's 1..4 TiB IOVA reservation; PA is declared. */
    qdev_prop_set_uint32(dev, "va-bits", 42);
    qdev_prop_set_uint32(dev, "pa-bits", 42);
    qdev_prop_set_uint32(dev, "revision", 2);
    sysbus_connect_irq(SYS_BUS_DEVICE(dev), 0,
                       qdev_get_gpio_in(s->aic, ldl_le_p(ints.data)));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, base);
    s->sep_dma_as = apple_dart_t8110_dma_as(s->sep_mapper, streams[0]);
    if (!s->sep_dma_as) {
        error_setg(errp, "modern SEP DART stream has no DMA address space");
        return false;
    }
    warn_report("apple-modern: opt-in SEP t8110 DART at 0x%" PRIx64
                " span 0x%" PRIx64 ", IRQ %u, mapper streams %u/%u; "
                "42-bit VA/PA and revision 2 are declared; no DAPF/TZ model",
                base, span, ldl_le_p(ints.data), streams[0], streams[1]);
    return true;
}

/*
 * SEP ASC mailbox, opt-in (sep-mailbox) and default off.
 *
 * This is the inter-processor message FIFO and its doorbell interrupt, not a
 * Secure Enclave: there is no SEP core, no sepOS, no firmware load and no
 * cryptography. A guest driver waiting for a sepOS boot message will still
 * wait forever.
 *
 * Geometry comes from the ADT. Register semantics come from XNU's own
 * AppleA7IOP driver in the pinned boot kernel collection; see
 * hw/misc/apple-silicon/a7iop/regs-v6.c for the measured offset inventory and
 * for what remains a declared choice.
 */
static bool map_sep_mailbox(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob reg, ints, compatible;
    uint64_t offset, size, base;
    Error *local = NULL;

    if (!apple_modern_adt_property(dtree, "/arm-io/sep", "reg", &reg, errp)) {
        return false;
    }
    if (reg.size != 32) {
        error_setg(errp, "unsupported modern SEP reg schema");
        return false;
    }
    /*
     * Window 0 only. Window 1 (measured at a uniform win0 - 0x5B0000 on every
     * ascwrap-v6 node in the tree) has entirely unknown contents and is left
     * unmodelled.
     */
    offset = ldq_le_p(reg.data);
    size = ldq_le_p(reg.data + 8);
    if (size < 0x10000 || size > 0x400000) {
        error_setg(errp, "modern SEP register span is out of range");
        return false;
    }
    if (!arm_io_translate(dtree, offset, size, &base, errp)) {
        return false;
    }
    /*
     * Accept a missing compatible: Darwin's device-tree fixup strips it from
     * /arm-io/sep on the tree the guest actually boots, so gating hard on it
     * would make the device vanish exactly when it is wanted.
     */
    if (apple_modern_adt_property(dtree, "/arm-io/sep", "compatible",
                                  &compatible, NULL)) {
        if (compatible.size < sizeof("iop-sep,ascwrap-v6") ||
            memcmp(compatible.data, "iop-sep,ascwrap-v6",
                   sizeof("iop-sep,ascwrap-v6"))) {
            error_setg(errp, "unsupported modern SEP wrapper (expected "
                       "iop-sep,ascwrap-v6)");
            return false;
        }
    } else {
        warn_report("apple-modern: /arm-io/sep has no compatible string; "
                    "assuming iop-sep,ascwrap-v6");
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/sep", "interrupts", &ints,
                                   errp)) {
        return false;
    }
    if (ints.size != 16) {
        error_setg(errp, "modern SEP names %zu interrupt bytes, expected 16",
                   (size_t)ints.size);
        return false;
    }
    if (!s->aic) {
        error_setg(errp, "sep-mailbox needs modern-aic: without a controller "
                   "no doorbell can be delivered");
        return false;
    }

    if (s->sep_sim) {
        /*
         * The SEP protocol simulator instead of a bare FIFO. It is an
         * AppleA7IOP subclass, so the geometry, the four lines and the
         * connect-before-realize ordering below are unchanged; only the
         * message handler differs. V6 is named explicitly: the simulator's
         * historical apple_sep_sim_from_node() boolean selects V4, which is
         * the wrong register layout for this board's ascwrap-v6 wrapper.
         *
         * Without sep-dart, out-of-line payloads use the system address space.
         * /arm-io/sep
         * names an iommu-parent and the tree has /arm-io/dart-sep, which this
         * board does not model, so an out-of-line address is treated as a
         * physical address rather than an IOVA. That is a declared
         * simplification: it is correct only while the guest's mapper is
         * identity. With sep-dart the normal mapper-sep IOVA address space is
         * used instead; disabled/invalid mappings reject DMA and raise the
         * modeled DART faults. Both modes leave the protocol simulator opt-in.
         */
        s->sep_mbox = DEVICE(apple_sep_sim_new("SEP", size, APPLE_A7IOP_V6,
                             s->sep_dart ? s->sep_dma_as :
                                           &address_space_memory));
    } else {
        s->sep_mbox = qdev_new(TYPE_APPLE_A7IOP);
        apple_a7iop_init(APPLE_A7IOP(s->sep_mbox), "SEP", size,
                         APPLE_A7IOP_V6, NULL, NULL);
    }

    /*
     * Positional mapping, and it is the measured one. XNU registers only two
     * of the four lines -- provider interrupt index 1 for the coprocessor's
     * inbox (our IOP_EMPTY, which wakes a blocked sender) and index 2 for its
     * outbox (our AP_NONEMPTY, the message doorbell). Our IRQ enum happens to
     * put IOP_EMPTY at 1 and AP_NONEMPTY at 2, so index i -> interrupts[i] is
     * correct for both lines XNU uses. Indices 0 and 3 are registered by
     * nothing, so their assignment is a declared choice.
     * The ADT carries no interrupt-names on any node in the tree, so the names
     * above are our reading of the driver's behaviour, not Apple's labels.
     */
    for (unsigned i = 0; i < APPLE_A7IOP_IRQ_MAX; i++) {
        uint32_t line = ldl_le_p(ints.data + i * 4);

        if (line >= s->aic_num_irqs) {
            error_setg(errp, "modern SEP interrupt %u is outside the %u "
                       "controller inputs", line, s->aic_num_irqs);
            return false;
        }
        sysbus_connect_irq(SYS_BUS_DEVICE(s->sep_mbox), i,
                           qdev_get_gpio_in(s->aic, line));
    }
    /*
     * Realize only after connecting. The device's four lines are the AP
     * mailbox's, re-exported through sysbus_pass_irq, and a connection made
     * after realize never reached those pins: measured, the AIC level word for
     * lines 320-351 stayed zero even after a queue change the mailbox itself
     * reported. The t8030 SEP connects first for the same reason.
     */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->sep_mbox), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->sep_mbox), 0, base);
    error_free(local);
    warn_report("apple-modern: SEP %s at 0x%" PRIx64 " size 0x%" PRIx64
                ", AIC inputs %u/%u/%u/%u (opt-in; the v6 register map is our "
                "declared layout, not Apple-documented%s)",
                s->sep_sim ? "protocol simulator" : "ASC mailbox",
                base, size, ldl_le_p(ints.data), ldl_le_p(ints.data + 4),
                ldl_le_p(ints.data + 8), ldl_le_p(ints.data + 12),
                s->sep_sim ? "; no sepOS, no firmware and no real "
                             "cryptography" : "");
    return true;
}

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
        /*
         * The mailbox device claims window 0, so step aside rather than
         * fighting it for the aperture. Window 1 is still worth observing:
         * nothing models it and its contents remain unexplained, which is the
         * one place where leaving a logging aperture mapped can still teach us
         * something.
         */
        if ((s->sep_mailbox || s->sep_sim) && i == 0) {
            continue;
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
    AppleModernAdtOverride overrides[APPLE_MODERN_MAX_ADT_OVERRIDES];
    const AppleModernAdtOverride *profile = NULL;
    size_t profile_count = 0, override_count = 0;
    uint8_t timebase_bytes[4];
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
    /*
     * Publish the acknowledge offset even when modern-aic is off: XNU's
     * AppleInterruptControllerV3 requires the property regardless of whether
     * we model the controller, and panics without it. Zero is refused here
     * rather than silently omitting the property, because the omission would
     * surface much later as that panic or as a confusing ADT lookup failure.
     */
    if (!s->aic_iack_offset) {
        error_report("apple-modern: aic-iack-offset must be nonzero; XNU "
                     "panics when the device-tree property is absent or zero");
        exit(EXIT_FAILURE);
    }
    metadata_input.aic_iack_offset = s->aic_iack_offset;
    if (s->pmgr_boot_on && !s->modern_pmgr) {
        error_report("apple-modern: pmgr-boot-on needs modern-pmgr=on; "
                     "otherwise there are no power cells to reset");
        exit(EXIT_FAILURE);
    }
    if (s->pmgr_voltage_states) {
        profile = apple_modern_pmgr_voltage_profile(s->pmgr_voltage_states,
                                                    &profile_count);
        if (!profile) {
            error_report("apple-modern: unknown pmgr-voltage-states profile "
                         "'%s' (supported: %s)", s->pmgr_voltage_states,
                         APPLE_MODERN_PMGR_VOLTAGE_J700);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: pmgr voltage-states from the measured "
                    "'%s' profile (MacBook Neo A18 Pro; analogy for "
                    "iPhone17,3, not an attested value)", s->pmgr_voltage_states);
    }
    for (size_t i = 0; i < profile_count; i++) {
        overrides[override_count++] = profile[i];
    }
    if (s->adt_timebase_match) {
        /*
         * XNU's clock and every deadline derive from the ADT value, while the
         * modelled generic counter runs at timebase-frequency; a template
         * tree whose value differs makes guest time run fast or slow.
         */
        stl_le_p(timebase_bytes, (uint32_t)s->timebase_frequency);
        overrides[override_count++] = (AppleModernAdtOverride){
            "/cpus/cpu0", "timebase-frequency", timebase_bytes,
            sizeof(timebase_bytes)};
    }
    if (override_count) {
        metadata_input.overrides = overrides;
        metadata_input.override_count = override_count;
    }
    if (!apple_modern_boot_metadata_build(&metadata_input, &s->metadata, &error) ||
        !uart_address(s->components.dtree, &uart, &uart_span, &s->uart_irq,
                      &error)) {
        error_report_err(error);
        exit(EXIT_FAILURE);
    }
    {
        AppleModernBlob tb;
        Error *tb_error = NULL;
        /* The tree itself was just validated, so a failed lookup means the
         * property is absent (XNU then has no timebase at all). */
        if (apple_modern_adt_property((AppleModernBlob){s->metadata.dtree,
                s->metadata.dtree_size}, "/cpus/cpu0", "timebase-frequency",
                &tb, &tb_error)) {
            uint64_t served = 0;
            for (size_t i = 0; i < tb.size && i < 8; i++) {
                served |= (uint64_t)tb.data[i] << (8 * i);
            }
            if (served != s->timebase_frequency) {
                warn_report("apple-modern: served ADT /cpus/cpu0 "
                            "timebase-frequency is %" PRIu64 " Hz but the "
                            "modelled counter runs at %" PRIu64 " Hz; guest "
                            "time will run %.2fx real time (set "
                            "adt-timebase-match=on to publish the counter "
                            "frequency)", served, s->timebase_frequency,
                            (double)s->timebase_frequency / (double)served);
            }
        } else {
            error_free(tb_error);
            warn_report("apple-modern: served ADT has no /cpus/cpu0 "
                        "timebase-frequency (iBoot normally supplies it)");
        }
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
        (s->sep_dart && !map_sep_dart(s, &error)) ||
        ((s->sep_mailbox || s->sep_sim) && !map_sep_mailbox(s, &error)) ||
        (s->sep_trace && !map_sep_trace(s, &error)) ||
        (s->modern_mcc_dramcfg && !map_mcc_dramcfg(s, uart, uart_span, &error)) ||
        (s->modern_mcc_quota && !map_mcc_quota(s, uart, uart_span, &error)) ||
        (s->modern_mcc_perf && !map_mcc_perf(s, uart, uart_span, &error)) ||
        (s->modern_mcc_socni && !map_mcc_socni(s, uart, uart_span, &error)) ||
        (s->modern_mcc_socni_command &&
         !map_mcc_socni_command(s, uart, uart_span, &error)) ||
        (s->modern_mcc_dcs_perf &&
         !map_mcc_dcs_perf(s, uart, uart_span, &error)) ||
        (s->modern_mcc_dsid && !map_mcc_dsid(s, uart, uart_span, &error)) ||
        (s->modern_mcc_slc && !map_mcc_slc(s, uart, uart_span, &error)) ||
        (s->modern_pmp_ptd && !map_pmp_ptd(s, uart, uart_span, &error)) ||
        (s->modern_cpu_dvfm && !map_cpu_dvfm(s, uart, uart_span, &error)) ||
        (s->modern_pmgr_storage &&
         !map_pmgr_storage(s, uart, uart_span, &error)) ||
        (s->pmgr_aon_fuse_image &&
         !map_pmgr_fuse(s, uart, uart_span, &error)) ||
        (s->modern_pmgr && !map_pmgr(s, uart, uart_span, &error))) {
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
    if (s->aic) {
        sysbus_connect_irq(SYS_BUS_DEVICE(s->aic), 0,
                           qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_IRQ));
    }
    /*
     * With the opt-in controller the UART drives its own ADT interrupt line
     * (uart0 "interrupts", 0x444 on this tree); otherwise the console stays
     * polled, as it was before the controller existed.
     */
    if (s->aic && s->uart_irq < s->aic_num_irqs) {
        warn_report("apple-modern: UART bound to AIC IRQ %u", s->uart_irq);
        apple_uart_create(uart, 15, 0, serial_hd(0),
                          qdev_get_gpio_in(s->aic, s->uart_irq));
    } else {
        if (s->aic) {
            warn_report("apple-modern: UART left polled (ADT interrupt %u is "
                        "outside the %u controller inputs)", s->uart_irq,
                        s->aic_num_irqs);
        }
        apple_uart_create(uart, 15, 0, serial_hd(0), NULL);
    }
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

static char *get_pmgr_aon_fuse_image(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->pmgr_aon_fuse_image);
}

static char *get_pmgr_voltage_states(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->pmgr_voltage_states);
}

static void set_pmgr_voltage_states(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->pmgr_voltage_states);
        s->pmgr_voltage_states = g_strdup(value);
    }
}

static char *get_pmgr_boot_on(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->pmgr_boot_on);
}

static void set_pmgr_boot_on(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->pmgr_boot_on);
        s->pmgr_boot_on = g_strdup(value);
    }
}

static void set_pmgr_aon_fuse_image(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->pmgr_aon_fuse_image);
        s->pmgr_aon_fuse_image = g_strdup(value);
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
BOOL_PROPERTY(sep_mailbox, sep_mailbox)
BOOL_PROPERTY(sep_sim, sep_sim)
BOOL_PROPERTY(sep_dart, sep_dart)
BOOL_PROPERTY(modern_pmgr, modern_pmgr)
BOOL_PROPERTY(modern_mcc_dramcfg, modern_mcc_dramcfg)
BOOL_PROPERTY(modern_mcc_quota, modern_mcc_quota)
BOOL_PROPERTY(modern_mcc_perf, modern_mcc_perf)
BOOL_PROPERTY(modern_mcc_socni, modern_mcc_socni)
BOOL_PROPERTY(modern_mcc_socni_command, modern_mcc_socni_command)
BOOL_PROPERTY(modern_mcc_dcs_perf, modern_mcc_dcs_perf)
BOOL_PROPERTY(adt_timebase_match, adt_timebase_match)
BOOL_PROPERTY(modern_pmp_ptd, modern_pmp_ptd)
BOOL_PROPERTY(modern_cpu_dvfm, modern_cpu_dvfm)
BOOL_PROPERTY(modern_pmgr_storage, modern_pmgr_storage)
BOOL_PROPERTY(modern_mcc_dsid, modern_mcc_dsid)
BOOL_PROPERTY(modern_mcc_slc, modern_mcc_slc)
BOOL_PROPERTY(aic_trace, aic_trace)
BOOL_PROPERTY(modern_aic, modern_aic)
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

static void get_perf_reset(Object *obj, Visitor *visitor, const char *name,
                           void *opaque, Error **errp)
{
    uint64_t value = APPLE_MODERN_MACHINE(obj)->mcc_perf_reset;
    visit_type_uint64(visitor, name, &value, errp);
}

static void set_perf_reset(Object *obj, Visitor *visitor, const char *name,
                           void *opaque, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    uint64_t value;
    if (check_mutable(s, errp) && visit_type_uint64(visitor, name, &value, errp)) {
        s->mcc_perf_reset = value;
    }
}

static void get_socni_reset(Object *obj, Visitor *visitor, const char *name,
                           void *opaque, Error **errp)
{
    uint64_t value = APPLE_MODERN_MACHINE(obj)->mcc_socni_reset;
    visit_type_uint64(visitor, name, &value, errp);
}

static void set_socni_reset(Object *obj, Visitor *visitor, const char *name,
                           void *opaque, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    uint64_t value;
    if (check_mutable(s, errp) && visit_type_uint64(visitor, name, &value, errp)) {
        s->mcc_socni_reset = value;
    }
}

static void get_dcs_perf_reset(Object *obj, Visitor *visitor, const char *name,
                               void *opaque, Error **errp)
{
    uint64_t value = APPLE_MODERN_MACHINE(obj)->mcc_dcs_perf_reset;
    visit_type_uint64(visitor, name, &value, errp);
}

static void set_dcs_perf_reset(Object *obj, Visitor *visitor, const char *name,
                               void *opaque, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    uint64_t value;
    if (check_mutable(s, errp) && visit_type_uint64(visitor, name, &value, errp)) {
        s->mcc_dcs_perf_reset = value;
    }
}

static void get_dsid_reset(Object *obj, Visitor *visitor, const char *name,
                           void *opaque, Error **errp)
{
    uint64_t value = APPLE_MODERN_MACHINE(obj)->mcc_dsid_reset;
    visit_type_uint64(visitor, name, &value, errp);
}

static void set_dsid_reset(Object *obj, Visitor *visitor, const char *name,
                           void *opaque, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    uint64_t value;
    if (check_mutable(s, errp) && visit_type_uint64(visitor, name, &value, errp)) {
        s->mcc_dsid_reset = value;
    }
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
    s->aic_revision = 3;
    s->aic_iack_offset = APPLE_MODERN_AIC_EVENT_OFFSET;
    s->timebase_frequency = 24000000; /* Configurable experiment value. */
    s->display_width = 1024;
    s->display_height = 768;
}

static void modern_finalize(Object *obj)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    apple_modern_boot_metadata_clear(&s->metadata);
    g_free(s->boot_command_line);
    g_free(s->pmgr_aon_fuse_image);
    g_free(s->pmgr_voltage_states);
    g_free(s->pmgr_boot_on);
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
    object_class_property_add_bool(oc, "modern-pmp-ptd", get_modern_pmp_ptd,
                                   set_modern_pmp_ptd);
    object_class_property_add_bool(oc, "modern-cpu-dvfm", get_modern_cpu_dvfm,
                                   set_modern_cpu_dvfm);
    object_class_property_add_bool(oc, "modern-pmgr-storage",
                                   get_modern_pmgr_storage, set_modern_pmgr_storage);
    object_class_property_add_bool(oc, "adt-timebase-match", get_adt_timebase_match,
                                   set_adt_timebase_match);
    object_class_property_add_str(oc, "pmgr-boot-on", get_pmgr_boot_on,
                                  set_pmgr_boot_on);
    object_class_property_add_str(oc, "pmgr-voltage-states",
                                  get_pmgr_voltage_states,
                                  set_pmgr_voltage_states);
    object_class_property_add_str(oc, "pmgr-aon-fuse-image",
                                   get_pmgr_aon_fuse_image,
                                   set_pmgr_aon_fuse_image);
    object_class_property_add_str(oc, "boot-command-line", get_boot_command_line,
                                  set_boot_command_line);
    object_class_property_add_bool(oc, "pauth-compat", get_pauth_compat,
                                   set_pauth_compat);
    object_class_property_add_bool(oc, "sep-trace", get_sep_trace,
                                   set_sep_trace);
    object_class_property_add_bool(oc, "sep-mailbox", get_sep_mailbox,
                                   set_sep_mailbox);
    object_class_property_add_bool(oc, "sep-sim", get_sep_sim, set_sep_sim);
    object_class_property_add_bool(oc, "sep-dart", get_sep_dart, set_sep_dart);
    object_class_property_add_bool(oc, "modern-pmgr", get_modern_pmgr,
                                   set_modern_pmgr);
    object_class_property_add_bool(oc, "modern-mcc-dramcfg", get_modern_mcc_dramcfg,
                                   set_modern_mcc_dramcfg);
    object_class_property_add(oc, "mcc-dramcfg-reset", "uint32",
                              get_display_geometry, set_display_geometry,
                              NULL, (void *)offsetof(AppleModernMachine,
                                                     mcc_dramcfg_reset));
    object_class_property_add_bool(oc, "modern-mcc-quota", get_modern_mcc_quota,
                                   set_modern_mcc_quota);
    object_class_property_add_bool(oc, "modern-mcc-perf", get_modern_mcc_perf,
                                   set_modern_mcc_perf);
    object_class_property_add(oc, "mcc-perf-reset", "uint64",
                             get_perf_reset, set_perf_reset, NULL, NULL);
    object_class_property_add_bool(oc, "modern-mcc-socni", get_modern_mcc_socni,
                                   set_modern_mcc_socni);
    object_class_property_add_bool(oc, "modern-mcc-socni-command",
                                   get_modern_mcc_socni_command,
                                   set_modern_mcc_socni_command);
    object_class_property_add(oc, "mcc-socni-reset", "uint64",
                             get_socni_reset, set_socni_reset, NULL, NULL);
    object_class_property_add_bool(oc, "modern-mcc-dcs-perf",
                                   get_modern_mcc_dcs_perf,
                                   set_modern_mcc_dcs_perf);
    object_class_property_add(oc, "mcc-dcs-perf-reset", "uint64",
                             get_dcs_perf_reset, set_dcs_perf_reset, NULL, NULL);
    object_class_property_add_bool(oc, "modern-mcc-dsid", get_modern_mcc_dsid,
                                   set_modern_mcc_dsid);
    object_class_property_add(oc, "mcc-dsid-reset", "uint64",
                             get_dsid_reset, set_dsid_reset, NULL, NULL);
    object_class_property_add_bool(oc, "modern-mcc-slc", get_modern_mcc_slc,
                                   set_modern_mcc_slc);
    object_class_property_add(oc, "mcc-quota-reset", "uint32",
                              get_display_geometry, set_display_geometry,
                              NULL, (void *)offsetof(AppleModernMachine,
                                                     mcc_quota_reset));
    object_class_property_add_bool(oc, "aic-trace", get_aic_trace,
                                   set_aic_trace);
    object_class_property_add_bool(oc, "modern-aic", get_modern_aic,
                                   set_modern_aic);
    object_class_property_add(oc, "aic-revision", "uint32",
                              get_display_geometry, set_display_geometry,
                              NULL, (void *)offsetof(AppleModernMachine,
                                                     aic_revision));
    object_class_property_add(oc, "aic-iack-offset", "uint32",
                              get_display_geometry, set_display_geometry,
                              NULL, (void *)offsetof(AppleModernMachine,
                                                     aic_iack_offset));
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
