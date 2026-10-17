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
#include "hw/arm/apple-silicon/modern-pmgr-ungate.h"
#include "hw/arm/apple-silicon/modern-pmp-ptd.h"
#include "hw/arm/apple-silicon/modern-cpu-dvfm.h"
#include "hw/arm/apple-silicon/modern-dcp-asc.h"
#include "hw/arm/apple-silicon/modern-dcp-iop.h"
#include "hw/arm/apple-silicon/modern-disp-trace.h"
#include "hw/arm/apple-silicon/modern-adt-sgx.h"
#include "hw/arm/apple-silicon/modern-adt-ioaccelerator-es.h"
#include "hw/arm/apple-silicon/modern-compat-groups.h"
#include "hw/arm/apple-silicon/modern-smc.h"
#include "hw/misc/apple-silicon/buttons.h"
#include "hw/arm/apple-silicon/modern-pmgr-storage.h"
#include "hw/arm/apple-silicon/modern-mcc-dsid.h"
#include "hw/arm/apple-silicon/modern-mcc-slc.h"
#include "hw/arm/apple-silicon/modern-kc-patch.h"
#include "hw/arm/apple-silicon/modern-image-patch.h"
#include "hw/intc/apple-modern-aic.h"
#include "hw/arm/apple-silicon/sep-sim.h"
#include "hw/arm/apple-silicon/dart-t8110.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/qdev-properties.h"
#include "hw/arm/apple-silicon/modern-boot-display.h"
#include "hw/arm/apple-silicon/modern-disp0.h"
#include "hw/arm/apple-silicon/modern-large-ramdisk.h"
#include "hw/arm/apple-silicon/dt.h"
#include "hw/arm/apple-silicon/dart.h"
#include "hw/arm/apple-silicon/sart.h"
#include "hw/pci-host/apcie.h"
#include "hw/block/apple-silicon/ans.h"
#include "hw/gpio/apple_gpio.h"
#include "hw/misc/apple-silicon/a7iop/base.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/msi.h"
#include "hw/nvme/nvme.h"
#include "system/block-backend.h"
#include "block/block.h"
#include "qobject/qdict.h"
#include "hw/char/apple_uart.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "system/system.h"
#include "cpu.h"

#define TYPE_APPLE_MODERN_MACHINE MACHINE_TYPE_NAME("apple-modern")
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernMachine, APPLE_MODERN_MACHINE)

enum ModernAsset {
    ASSET_BOOTKC, ASSET_SPTM, ASSET_TXM, ASSET_DTREE, ASSET_TC, ASSET_RAMDISK,
    /*
     * Optional: a second Apple trust-cache module, published behind the same
     * catalog offsets header as `tc`. See the cryptex-trustcache property.
     */
    ASSET_CRYPTEX_TC,
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
    /* Created by the machine core (mc->default_ram_id), not by the board. */
    MemoryRegion *ram;
    MemoryRegion tag_memory, tag_ram;
    /*
     * Opt-in: the ramdisk is a read-only host file mapping published as its
     * own RAM region over the DRAM window, never copied into guest RAM.
     */
    bool large_ramdisk;
    AppleModernLargeRamdisk large_ramdisk_file;
    /* Optional list of declared in-memory edits to the large ramdisk. */
    char *ramdisk_patches;
    MemoryRegion large_ramdisk_mr;
    MemoryRegion cpu_register_ram[APPLE_MODERN_CPU_REGISTER_WINDOWS];
    MemoryRegion aic_ram, sep_ram;
    MemoryRegion sep_trace_mr[2];
    unsigned sep_trace_count;
    AppleModernAMCC amcc;
    bool has_amcc;
    bool img4_ignition_compat;
    bool trustcache_v2;
    bool md0_width_compat;
    bool root_rw_compat;
    bool txm_sc_compat;
    bool iouc_sandbox_compat;
    bool amfi_csstatus_platform_compat;
    bool platform_binary_force_compat;
    bool rootvp_auth_skip_compat;
    bool vekd_unenc_data_compat;
    bool keystore_persona_stub_compat;
    bool modern_ans;
    char *modern_ans_image;
    /* Declared, opt-in anchored image-patch set (default NULL = none). */
    char *image_patches;
    AppleModernImagePatchResult image_patch_result;
    bool pauth_compat;
    /* Read-only observability, default off: trace EL0 BRK traps. */
    bool el0_trap_trace;
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
    /*
     * Declared disp0 bind probe (default off): restores the display nodes'
     * stock "compatible" strings and maps the disp0 / dcp0-expert register
     * windows as logging apertures. See modern-disp-trace.h.
     */
    char *disp0_probe;
    /* w14-compatsweep: '+'-separated ADT compatible-restore group list. */
    char *adt_compat_restore;
    bool modern_smc;
    bool modern_smc_buttons;
    AppleModernSMCPlan smc_plan;
    AppleModernDispTracePlan disp_trace_plan;
    /*
     * Declared, default-off ASC v6 wrapper apertures over the three
     * /arm-io/dcp register windows (w12-dcp).  See modern-dcp-asc.h: three
     * decoded registers, an empty mailbox with no peer, no endpoint.
     */
    char *dcp_asc;
    AppleModernDcpAscPlan dcp_asc_plan;
    /*
     * Declared, default-off RTKit peer on /arm-io/dcp (w14-endpoint).  Unlike
     * dcp-asc this one answers: it owns reg[0] with the in-tree a7iop register
     * file, runs the existing RTKit management handshake and advertises one
     * user endpoint.  See modern-dcp-iop.h for the derivation of the endpoint
     * number and for the two declared ADT flags.
     */
    char *dcp_iop;
    /*
     * v6-resumed display-attach callbacks ('+'-separated subset of
     * D575/D600, default none) and when to send them
     * ("normal-mode" = nested in NormalModeEnable, "a453" = nested in the
     * first get_display_size after it).  See modern-dcp-iop.c.
     */
    char *dcp_attach_cbs;
    char *dcp_attach_trigger;
    AppleModernDcpIopPlan dcp_iop_plan;
    DeviceState *dcp_iop_dev;
    bool dcp_iop_mapped;
    /* Declared storage for the PMGR perf-counter registers ApplePMGR programs. */
    bool modern_pmgr_storage;
    AppleModernPMGRStoragePlan pmgr_storage_plan;
    /* Declared reset profile naming PMGR domains iBoot leaves powered on. */
    char *pmgr_boot_on;
    /* Publish the modelled counter frequency as /cpus/cpu0 timebase-frequency. */
    bool adt_timebase_match;
    /* Serve /chosen sepfw-load-at-boot = 0: declare that no SEP firmware runs. */
    bool sepfw_absent;
    /* Serve a unique dart-id on every dart,t8110 node (ADT order, declared). */
    bool adt_dart_ids;
    /*
     * Declared guest modification: serve /arm-io no-clock-gate and
     * no-power-gate so AppleH17PPlatformIO::start skips resolving
     * function-clock_gate / function-power_gate (AppleT8140,
     * AppleH17PPlatformIO.cpp:94 and :100). Removes the kernel's ability to
     * clock- or power-gate any /arm-io device through /arm-io/pmgr, and with
     * it the panic those two absent properties otherwise cause.
     */
    bool pmgr_ungate;
    AppleModernPMGRFusePlan pmgr_fuse_plan;
    AppleDARTT8110State *sep_mapper;
    AddressSpace *sep_dma_as;
    AppleDARTT8110State *dcp_mapper;
    AddressSpace *dcp_dma_as;
    uint64_t dcp_dart_address, dcp_dart_size;
    AppleDARTT8110State *disp0_mapper;
    AddressSpace *disp0_dma_as;
    uint64_t disp0_dart_address, disp0_dart_size;
    DeviceState *sep_mbox;
    /*
     * Opt-in GPU coprocessor mailbox (gfx-asc). See map_gfx_mailbox().
     */
    bool gfx_asc;
    DeviceState *gfx_mbox;
    /* gfx-asc reg[1], the ASCWrap core register. See map_gfx_core(). */
    MemoryRegion gfx_core_mr;
    /* Opt-in GPU/UAT carveout (unmanaged DRAM tail). See map_gfx_core()'s
     * sibling note and gfx_carveout_size in modern-boot-metadata.h. */
    bool gfx_carveout;
    /*
     * Opt-in logging aperture over the GPU register windows, independent of
     * sgx=on so it can back a node served under another name. The driver
     * polls GPU registers during probe -- measured, the guest wedges forever
     * on a single `ldr w23,[x8]` at win0+0xd04000 with the aperture absent.
     */
    bool gpu_trace;
    /* Answer the probed GPU registers non-zero; see sgx_trace_read(). */
    bool gpu_trace_answer;
    /*
     * Opt-in GPU node (/arm-io/sgx). See modern-adt-sgx.h and map_sgx_trace().
     */
    bool sgx;
    MemoryRegion sgx_trace_mr[2];
    unsigned sgx_trace_count;
    /*
     * Opt-in /arm-io/IOAcceleratorES nub for QC NameMatching fail-fast.
     * Mutually exclusive with sgx=on (both use added_node). See
     * modern-adt-ioaccelerator-es.h.
     */
    bool stub_ioacceles;
    /* Serve /chosen gpu-iouat = 0 (SPTM UAT off). See modern-adt-sgx.h. */
    bool gpu_iouat_zero;
    bool aic_trace;
    bool modern_aic;
    /* Opt-in: accept and record nonzero IRQ_CFG words (see apple-modern-aic.h). */
    bool aic_record_irq_config;
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
    /* Opt-in T8140 disp0 unified display pipe (W-08). */
    bool disp0_pipe;
    DeviceState *disp0;
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
        /*
         * The mapped ramdisk region is its own read-only host file mapping:
         * zero-filling or copying it would fault in and privately dirty every
         * page of a multi-gigabyte image on each reset.
         */
        if (s->large_ramdisk && !strcmp(r->name, "RAMDisk")) {
            continue;
        }
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
        if (s->large_ramdisk && copy->image == APPLE_MODERN_RAMDISK) {
            continue; /* Already in guest RAM as a host file mapping. */
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

/*
 * modern-ans (EXPERIMENTAL, OPT-IN): wire an Apple ANS/NVMe storage controller
 * into apple-modern by reusing the in-tree apcie.c/ans.c/sart.c creators. The
 * creators take an AppleDTNode tree and self-map MMIO using reg[] as ABSOLUTE
 * addresses, but apple-modern's blob ADT stores reg[] as /arm-io OFFSETS, so we
 * deserialise the blob, translate each node's reg[] offset->absolute via
 * arm_io_translate, then call the creators. Goal: let iOS enumerate the APFS
 * container on NVMe so the Data volume mounts (gate-3). No NVMe namespace
 * backing is attached yet -- this first wires the controller to test whether
 * iOS initiates ANS traffic at all. Compatibility/experimental, not fidelity.
 */
static bool modern_ans_absolutize_regs(AppleModernBlob dtree, AppleDTNode *node,
                                       Error **errp)
{
    AppleDTProp *reg = apple_dt_get_prop(node, "reg");
    uint64_t *r;
    size_t pairs, i;

    if (!reg || !reg->data || (reg->len % 16) != 0 || reg->len == 0) {
        error_setg(errp, "modern-ans: node has no usable reg property");
        return false;
    }
    r = (uint64_t *)reg->data;
    pairs = reg->len / 16;
    for (i = 0; i < pairs; i++) {
        uint64_t abs;
        if (!arm_io_translate(dtree, r[i * 2], r[i * 2 + 1], &abs, errp)) {
            return false;
        }
        r[i * 2] = abs;
    }
    return true;
}

/* Create one apcie DART (generic apple-dart) and register it as the machine
 * link "dart-apcieN" that apple_pcie_create_port() looks up. Absent node -> skip. */
static bool modern_create_apcie_dart(AppleModernMachine *s, AppleModernBlob dtree,
                                     AppleDTNode *dt, const char *name,
                                     Error **errp)
{
    char path[32];
    AppleDTNode *n;
    AppleDARTState *dart;
    AppleDTProp *prop;
    uint64_t *r;
    size_t i;

    snprintf(path, sizeof(path), "arm-io/%s", name);
    n = apple_dt_get_node(dt, path);
    if (!n) {
        return true; /* not all ports present; skip missing DARTs */
    }
    prop = apple_dt_get_prop(n, "vm-base");
    if (prop && prop->data && prop->len >= 4 && ldl_le_p(prop->data) == 0) {
        stl_le_p(prop->data, 0x4000);
    }
    if (!modern_ans_absolutize_regs(dtree, n, errp)) {
        return false;
    }
    dart = apple_dart_from_node(n);
    if (!dart) {
        error_setg(errp, "modern-ans: %s create failed", name);
        return false;
    }
    object_property_add_child(qdev_get_machine(), name, OBJECT(dart));
    r = (uint64_t *)apple_dt_get_prop(n, "reg")->data;
    prop = apple_dt_get_prop(n, "reg");
    for (i = 0; i < prop->len / 16; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dart), i, r[i * 2]);
    }
    if ((prop = apple_dt_get_prop(n, "interrupts")) && prop->data) {
        uint32_t *ii = (uint32_t *)prop->data;
        for (i = 0; i < prop->len / sizeof(uint32_t); i++) {
            if (ii[i] < s->aic_num_irqs) {
                sysbus_connect_irq(SYS_BUS_DEVICE(dart), i,
                                   qdev_get_gpio_in(s->aic, ii[i]));
            }
        }
    }
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dart), &error_fatal);
    return true;
}

static bool modern_create_ans(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleDTNode *dt, *apcie, *sartn, *ansn, *chosen;
    AppleDTProp *prop;
    SysBusDevice *pcie, *sart, *ans;
    uint32_t chip_id = 0;
    uint64_t *r;
    size_t i;

    dt = apple_dt_deserialise(s->metadata.dtree);
    if (!dt) {
        error_setg(errp, "modern-ans: device-tree deserialise failed");
        return false;
    }
    chosen = apple_dt_get_node(dt, "chosen");
    if (chosen && (prop = apple_dt_get_prop(chosen, "chip-id")) && prop->data &&
        prop->len >= 4) {
        chip_id = ldl_le_p(prop->data);
    }

    /* --- PCIe host (apple_pcie_from_node self-maps absolute reg + registers
       pcie.host / pcie.bridgeN on the machine object) --- */
    apcie = apple_dt_get_node(dt, "arm-io/apcie");
    if (!apcie) {
        error_setg(errp, "modern-ans: /arm-io/apcie node missing");
        return false;
    }
    apple_dt_set_prop_null(apcie, "apcie-phy-tunables");
    if (!modern_ans_absolutize_regs(dtree, apcie, errp)) {
        return false;
    }
    /* apple_pcie_create_port() looks up machine links "dart-apcieN" per port;
       create them first (generic apple-dart) from the dtree. */
    if (!modern_create_apcie_dart(s, dtree, dt, "dart-apcie0", errp) ||
        !modern_create_apcie_dart(s, dtree, dt, "dart-apcie1", errp) ||
        !modern_create_apcie_dart(s, dtree, dt, "dart-apcie2", errp)) {
        return false;
    }
    /* apcie clkreq handling looks up machine link "gpio"; provide it from the
       t8140 gpio0 node (registered under the name apcie expects). */
    {
        AppleDTNode *g = apple_dt_get_node(dt, "arm-io/gpio0");
        if (g && modern_ans_absolutize_regs(dtree, g, errp)) {
            DeviceState *gpio = apple_gpio_from_node(g);
            if (gpio) {
                object_property_add_child(qdev_get_machine(), "gpio",
                                          OBJECT(gpio));
                r = (uint64_t *)apple_dt_get_prop(g, "reg")->data;
                sysbus_mmio_map(SYS_BUS_DEVICE(gpio), 0, r[0]);
                if ((prop = apple_dt_get_prop(g, "interrupts")) && prop->data) {
                    uint32_t *ii = (uint32_t *)prop->data;
                    for (i = 0; i < prop->len / sizeof(uint32_t); i++) {
                        if (ii[i] < s->aic_num_irqs) {
                            sysbus_connect_irq(SYS_BUS_DEVICE(gpio), i,
                                               qdev_get_gpio_in(s->aic, ii[i]));
                        }
                    }
                }
                sysbus_realize_and_unref(SYS_BUS_DEVICE(gpio), &error_fatal);
            }
        } else if (g == NULL) {
            error_setg(errp, "modern-ans: /arm-io/gpio0 node missing");
            return false;
        } else {
            return false;
        }
    }
    msi_nonbroken = true; /* apcie/nvme use MSI; AIC delivers via msi-vector-offset */
    pcie = apple_pcie_from_node(apcie, chip_id);
    if (!pcie) {
        error_setg(errp, "modern-ans: apple_pcie_from_node failed");
        return false;
    }
    {
        uint32_t nreg = 0, msi_off = 0, msi_vec = 0;
        /* apcie host sysbus IRQ layout is FIXED: [0..3]=irqs[4], [4..35]=msi_irqs[8*4]. */
        if ((prop = apple_dt_get_prop(apcie, "interrupts")) && prop->data) {
            uint32_t *ii = (uint32_t *)prop->data;
            nreg = prop->len / sizeof(uint32_t);
            if (nreg > 4) {
                nreg = 4;
            }
            for (i = 0; i < nreg; i++) {
                if (ii[i] < s->aic_num_irqs) {
                    sysbus_connect_irq(pcie, i, qdev_get_gpio_in(s->aic, ii[i]));
                }
            }
        }
        if ((prop = apple_dt_get_prop(apcie, "msi-vector-offset")) &&
            prop->data && prop->len >= 4) {
            msi_off = ldl_le_p(prop->data);
        }
        if ((prop = apple_dt_get_prop(apcie, "#msi-vectors")) && prop->data &&
            prop->len >= 4) {
            msi_vec = ldl_le_p(prop->data);
        }
        if (msi_vec > 8 * APCIE_MAX_PORTS) {
            msi_vec = 8 * APCIE_MAX_PORTS;
        }
        for (i = 0; i < msi_vec; i++) {
            if (msi_off + i < s->aic_num_irqs) {
                sysbus_connect_irq(pcie, 4 + i,
                                   qdev_get_gpio_in(s->aic, msi_off + i));
            }
        }
    }

    /* --- SART (caller maps reg[0]) --- */
    sartn = apple_dt_get_node(dt, "arm-io/sart-ans");
    if (!sartn) {
        error_setg(errp, "modern-ans: /arm-io/sart-ans node missing");
        return false;
    }
    if (!modern_ans_absolutize_regs(dtree, sartn, errp)) {
        return false;
    }
    sart = apple_sart_from_node(sartn);
    if (!sart) {
        error_setg(errp, "modern-ans: apple_sart_from_node failed");
        return false;
    }
    r = (uint64_t *)apple_dt_get_prop(sartn, "reg")->data;
    sysbus_mmio_map(sart, 0, r[0]);
    sysbus_realize_and_unref(sart, &error_fatal);

    /* --- ANS (needs a PCI sec_bus from the pcie bridge; caller maps 4 regs) --- */
    ansn = apple_dt_get_node(dt, "arm-io/ans");
    if (!ansn) {
        error_setg(errp, "modern-ans: /arm-io/ans node missing");
        return false;
    }
    if (!modern_ans_absolutize_regs(dtree, ansn, errp)) {
        return false;
    }
    {
        Object *brd_o = object_property_get_link(qdev_get_machine(),
                                                 "pcie.bridge0", NULL);
        PCIBus *sec;
        Object *host_o;
        if (!brd_o) {
            error_setg(errp, "modern-ans: pcie.bridge0 link absent "
                       "(apcie created no bridge0)");
            return false;
        }
        sec = pci_bridge_get_sec_bus(PCI_BRIDGE(brd_o));
        ans = apple_ans_from_node(ansn, APPLE_A7IOP_V6, sec);
        if (!ans) {
            error_setg(errp, "modern-ans: apple_ans_from_node failed");
            return false;
        }
        object_property_add_const_link(OBJECT(ans), "dma-mr",
                                       OBJECT(sysbus_mmio_get_region(sart, 1)));
        r = (uint64_t *)apple_dt_get_prop(ansn, "reg")->data;
        for (i = 0; i < 4; i++) {
            sysbus_mmio_map(ans, i, r[i << 1]);
        }
        if ((prop = apple_dt_get_prop(ansn, "interrupts")) && prop->data) {
            uint32_t *ii = (uint32_t *)prop->data;
            for (i = 0; i < prop->len / sizeof(uint32_t); i++) {
                if (ii[i] < s->aic_num_irqs) {
                    sysbus_connect_irq(ans, i, qdev_get_gpio_in(s->aic, ii[i]));
                }
            }
        }
        host_o = object_property_get_link(qdev_get_machine(), "pcie.host", NULL);
        if (host_o) {
            qdev_connect_gpio_out_named(
                DEVICE(host_o), "interrupt_pci", 0,
                qdev_get_gpio_in_named(DEVICE(ans), "interrupt_pci", 0));
        }
        sysbus_realize_and_unref(ans, &error_fatal);
    }

    /* Optional: back the ANS NVMe with an APFS image as nsid 1 (readonly, so the
       source image is never mutated) so iOS can enumerate a real namespace. */
    if (s->modern_ans_image && s->modern_ans_image[0]) {
        Object *nvme_o = object_resolve_path_component(OBJECT(ans), "nvme");
        BlockBackend *blk;
        DeviceState *ns;

        if (!nvme_o) {
            error_setg(errp, "modern-ans: nvme child not found on ans");
            return false;
        }
        {
            /* These "dmg" files are RAW APFS images, not UDIF DMGs -- force the
               raw driver over a plain file so QEMU does not probe them as dmg. */
            QDict *opts = qdict_new();
            qdict_put_str(opts, "driver", "raw");
            qdict_put_str(opts, "file.driver", "file");
            qdict_put_str(opts, "file.filename", s->modern_ans_image);
            blk = blk_new_open(NULL, NULL, opts, 0, errp);
        }
        if (!blk) {
            return false;
        }
        ns = qdev_new(TYPE_NVME_NS);
        qdev_prop_set_drive(ns, "drive", blk);
        qdev_prop_set_uint32(ns, "nsid", 1);
        qdev_realize_and_unref(ns, BUS(&NVME(nvme_o)->bus), &error_fatal);
        warn_report("apple-modern: modern-ans attached nvme-ns nsid 1 (readonly) "
                    "backed by %s", s->modern_ans_image);
    }

    warn_report("apple-modern: opt-in modern-ans wired apcie+sart+ans "
                "(chip 0x%08x); EXPERIMENTAL IOKit storage controller, no NVMe "
                "namespace backing yet. Compatibility, not Apple fidelity",
                chip_id);
    return true;
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
    for (size_t i = 0; i < APPLE_MODERN_SMC_WINDOWS; i++) {
        if (s->smc_plan.size[i] && !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->smc_plan.address[i], s->smc_plan.size[i]}, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < s->dcp_asc_plan.count; i++) {
        if (s->dcp_asc_plan.contained[i]) {
            continue;
        }
        if (!append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){s->dcp_asc_plan.addresses[i],
                                         s->dcp_asc_plan.sizes[i]}, errp)) {
            return false;
        }
    }
    if (s->dcp_iop_mapped &&
        !append_pmgr_exclusion(exclusions, &count,
            (AppleModernAddressRange){s->dcp_iop_plan.wrapper_address,
                                     s->dcp_iop_plan.wrapper_size}, errp)) {
        return false;
    }
    if (s->dcp_iop_mapped && s->dcp_iop_plan.expert_control_address &&
        !append_pmgr_exclusion(exclusions, &count,
            (AppleModernAddressRange){s->dcp_iop_plan.expert_control_address,
                                     4}, errp)) {
        return false;
    }
    if (s->dcp_iop_mapped && s->dcp_iop_plan.core_address &&
        !append_pmgr_exclusion(exclusions, &count,
            (AppleModernAddressRange){s->dcp_iop_plan.core_address,
                                     s->dcp_iop_plan.core_size}, errp)) {
        return false;
    }
    if (s->dcp_iop_mapped && s->dcp_iop_plan.segment_address &&
        !append_pmgr_exclusion(exclusions, &count,
            (AppleModernAddressRange){s->dcp_iop_plan.segment_address,
                                     s->dcp_iop_plan.segment_size}, errp)) {
        return false;
    }
    if (s->dcp_dart_size &&
        !append_pmgr_exclusion(exclusions, &count,
            (AppleModernAddressRange){s->dcp_dart_address,
                                     s->dcp_dart_size}, errp)) {
        return false;
    }
    if (s->disp0_dart_size &&
        !append_pmgr_exclusion(exclusions, &count,
            (AppleModernAddressRange){s->disp0_dart_address,
                                     s->disp0_dart_size}, errp)) {
        return false;
    }
    for (unsigned i = 0; i < s->disp_trace_plan.count; i++) {
        const AppleModernDispTraceWindow *w = &s->disp_trace_plan.windows[i];
        if (w->status == APPLE_MODERN_DISP_TRACE_MAPPED &&
            !append_pmgr_exclusion(exclusions, &count,
                (AppleModernAddressRange){w->physical_address, w->size}, errp)) {
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

/*
 * Opt-in T8140 disp0 unified display pipe (ledger item W-08). The plan comes
 * from the served ADT; only the windows this model owns are mapped, and every
 * offset it does not represent FAULTS so the next real guest requirement shows
 * up as a frontier record instead of a silent zero.
 */
static bool map_disp0(AppleModernMachine *s, uint64_t uart, uint64_t uart_span,
                      Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernDisp0Plan plan;
    size_t count;
    uint32_t stride = s->display_stride ? s->display_stride :
                                          s->display_width * 4;

    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_disp0_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    if (!s->metadata.layout.framebuffer_size) {
        error_setg(errp, "disp0-pipe needs a framebuffer reservation");
        return false;
    }
    s->disp0 = apple_modern_disp0_new(&plan, s->ram,
        s->metadata.layout.framebuffer_physical - s->components.dram_base,
        s->display_width, s->display_height, stride, serial_hd(0));
    s->disp0->id = g_strdup("disp0");
    object_property_add_child(OBJECT(s), "disp0", OBJECT(s->disp0));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->disp0), &error_fatal);
    for (unsigned i = 0, slot = 0; i < APPLE_MODERN_DISP0_WINDOWS; i++) {
        if (plan.windows[i].mapped) {
            sysbus_mmio_map(SYS_BUS_DEVICE(s->disp0), slot++,
                            plan.windows[i].address);
        }
    }
    if (s->aic) {
        for (unsigned i = 0; i < APPLE_MODERN_DISP0_IRQS; i++) {
            if (plan.interrupts[i] < s->aic_num_irqs) {
                sysbus_connect_irq(SYS_BUS_DEVICE(s->disp0), i,
                    qdev_get_gpio_in(s->aic, plan.interrupts[i]));
            }
        }
    }
    warn_report("apple-modern: opt-in disp0 pipe, %u of %u windows mapped, "
                "%u shadow aliases, dot pitch %u; every unmodelled offset "
                "faults. Register offsets are ANALOGY from the in-tree "
                "A13/t8030 model, not attested for T8140",
                plan.mapped_count, APPLE_MODERN_DISP0_WINDOWS,
                plan.shadow_copies, plan.dot_pitch);
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

/*
 * Mapped BEFORE map_disp_trace so that the three /arm-io/dcp windows become
 * board exclusions: disp0 reg[4] contains all three of them, and the trace
 * plan must then skip reg[4] rather than answer the wrapper's registers with
 * a logging aperture's zero.  Every skip is reported by map_disp_trace itself.
 */
static bool map_dcp_asc(AppleModernMachine *s, uint64_t uart,
                        uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernDcpAscPlan plan;
    size_t count;
    unsigned mode = 0;
    DeviceState *dev;

    if (!apple_modern_dcp_asc_mode(s->dcp_asc, &mode)) {
        error_setg(errp, "unknown dcp-asc mode '%s' (supported: %s)",
                   s->dcp_asc, APPLE_MODERN_DCP_ASC_MODE_NAMES);
        return false;
    }
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_dcp_asc_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    dev = apple_modern_dcp_asc_new(&plan, mode);
    /* The child's name must NOT collide with the board property of the same
     * name: object_property_add_child() aborts with "attempt to add duplicate
     * property 'dcp-asc'". Caught by the whole-machine gate's g3 arm. */
    dev->id = g_strdup("dcp-asc-dev");
    object_property_add_child(OBJECT(s), "dcp-asc-dev", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0, region = 0; i < plan.count; i++) {
        warn_report("apple-modern: dcp-asc candidate reg[%u] %s 0x%" PRIx64
                    "+0x%" PRIx64 " %s", i,
                    apple_modern_dcp_asc_window_name(i), plan.addresses[i],
                    plan.sizes[i], plan.contained[i] ?
                    "skipped: inside an earlier window" : "mapped");
        if (!plan.contained[i]) {
            sysbus_mmio_map(SYS_BUS_DEVICE(dev), region++, plan.addresses[i]);
        }
    }
    s->dcp_asc_plan = plan;
    warn_report("apple-modern: opt-in dcp-asc '%s': a handful of decoded "
                "registers over the /arm-io/dcp ASC v6 windows (reg[2] is "
                "inside reg[0], so TWO apertures), an EMPTY mailbox with no "
                "peer and NO published endpoint; core offset 0 bit 0 = %u is a "
                "DECLARED claim that iBoot pre-loaded the DCP firmware, which "
                "this loader does not do", s->dcp_asc,
                mode == APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED ? 1u : 0u);
    return true;
}
static bool map_modern_smc(AppleModernMachine *s, uint64_t uart,
                           uint64_t uart_span, Error **errp)
{
    AppleModernBlob tree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernSMCPlan plan;
    size_t count;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_smc_plan_build(tree, s->components.dram_base,
                                    s->components.dram_size,
                                    exclusions, count, &plan, errp)) {
        return false;
    }
    for (size_t i = 0; i < APPLE_MODERN_SMC_IRQS; i++) {
        if (plan.interrupts[i] >= s->aic_num_irqs) {
            error_setg(errp, "modern-smc IRQ %u exceeds the AIC bound", plan.interrupts[i]);
            return false;
        }
    }
    SysBusDevice *dev = apple_modern_smc_new(&plan);
    object_property_add_child(OBJECT(s), "modern-smc-dev", OBJECT(dev));
    sysbus_realize_and_unref(dev, &error_fatal);
    const unsigned index[] = {0, 1, 3, 2};
    for (size_t i = 0; i < APPLE_MODERN_SMC_WINDOWS; i++) {
        sysbus_mmio_map(dev, index[i], plan.address[i]);
    }
    for (size_t i = 0; i < APPLE_MODERN_SMC_IRQS; i++) {
        sysbus_connect_irq(dev, i, qdev_get_gpio_in(s->aic, plan.interrupts[i]));
    }
    s->smc_plan = plan;
    if (s->modern_smc_buttons) {
        /* Reuse the legacy input/key implementation; notification ABI is an
         * explicit analogy until runtime packet consumption is measured. */
        object_property_add_const_link(OBJECT(s), "smc", OBJECT(dev));
        SysBusDevice *buttons = apple_buttons_create(NULL);
        object_property_add_child(OBJECT(s), "modern-smc-buttons-dev",
                                  OBJECT(buttons));
        sysbus_realize_and_unref(buttons, &error_fatal);
    }
    warn_report("apple-modern: modern-smc uses legacy SMC key HLE with V6 mailbox; "
                "wrapper/core/timers/SRAM 0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64 "; "
                "pre-loaded/running/core-loaded are DECLARED, no SMC firmware placed; "
                "timers unmodelled, modern input acceptance unqualified",
                plan.address[0], plan.address[1], plan.address[2], plan.address[3]);
    return true;
}
static bool map_dcp_dart(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob reg, ints, value, parents;
    uint64_t dcp_base, dcp_offset, dcp_span;
    uint64_t disp0_base, disp0_offset, disp0_span;
    uint32_t dcp_num_streams, dcp_stream, dcp_phandle;
    uint32_t disp0_num_streams, disp0_streams[2], disp0_phandles[2];
    static const char *disp0_mapper_paths[] = {
        "/arm-io/dart-disp0/mapper-disp0",
        "/arm-io/dart-disp0/mapper-disp0-piodma",
    };

    if (!s->aic) {
        error_setg(errp, "dcp-iop v6-resumed DART requires modern-aic");
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-dcp", "reg",
                                   &reg, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/dart-dcp", "interrupts",
                                   &ints, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/dcp", "iommu-parent",
                                   &parents, errp)) {
        return false;
    }
    if (reg.size != 16 || ints.size != 4 || parents.size != 4) {
        error_setg(errp, "unsupported DCP DART reg/IRQ/mapper schema");
        return false;
    }
    dcp_offset = ldq_le_p(reg.data);
    dcp_span = ldq_le_p(reg.data + 8);
    if (dcp_span < 0x1800 || dcp_span > 0x400000 ||
        ldl_le_p(ints.data) >= s->aic_num_irqs ||
        !arm_io_translate(dtree, dcp_offset, dcp_span, &dcp_base, errp)) {
        if (!errp || !*errp) {
            error_setg(errp, "modern DCP DART geometry exceeds supported bounds");
        }
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-dcp", "page-size",
                                   &value, errp) ||
        value.size != 4 || ldl_le_p(value.data) != 0x4000) {
        if (!errp || !*errp) {
            error_setg(errp, "modern DCP DART supports only 16 KiB pages");
        }
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-dcp", "sid-count",
                                   &value, errp) ||
        value.size != 4 || !(dcp_num_streams = ldl_le_p(value.data)) ||
        dcp_num_streams > APPLE_DART_T8110_STREAMS) {
        if (!errp || !*errp) {
            error_setg(errp, "modern DCP DART sid-count is out of range");
        }
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-dcp/mapper-dcp",
                                   "AAPL,phandle", &value, errp) ||
        value.size != 4) {
        if (!errp || !*errp) {
            error_setg(errp, "modern DCP DART mapper phandle must be u32");
        }
        return false;
    }
    dcp_phandle = ldl_le_p(value.data);
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-dcp/mapper-dcp",
                                   "reg", &value, errp) ||
        value.size != 4 ||
        (dcp_stream = ldl_le_p(value.data)) >= dcp_num_streams ||
        ldl_le_p(parents.data) != dcp_phandle) {
        if (!errp || !*errp) {
            error_setg(errp, "modern DCP iommu-parent must resolve to "
                       "mapper-dcp with an in-range stream");
        }
        return false;
    }

    if (!apple_modern_adt_property(dtree, "/arm-io/dart-disp0", "reg",
                                   &reg, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/disp0", "iommu-parent",
                                   &parents, errp)) {
        return false;
    }
    if (reg.size < 16 || reg.size % 16 || parents.size != 8) {
        error_setg(errp, "unsupported disp0 DART reg/mapper schema");
        return false;
    }
    disp0_offset = ldq_le_p(reg.data);
    disp0_span = ldq_le_p(reg.data + 8);
    if (disp0_span < 0x1800 || disp0_span > 0x400000 ||
        !arm_io_translate(dtree, disp0_offset, disp0_span, &disp0_base, errp)) {
        if (!errp || !*errp) {
            error_setg(errp, "modern disp0 DART geometry exceeds supported bounds");
        }
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-disp0", "page-size",
                                   &value, errp) ||
        value.size != 4 || ldl_le_p(value.data) != 0x4000) {
        if (!errp || !*errp) {
            error_setg(errp, "modern disp0 DART supports only 16 KiB pages");
        }
        return false;
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/dart-disp0", "sid-count",
                                   &value, errp) ||
        value.size != 4 || !(disp0_num_streams = ldl_le_p(value.data)) ||
        disp0_num_streams > APPLE_DART_T8110_STREAMS) {
        if (!errp || !*errp) {
            error_setg(errp, "modern disp0 DART sid-count is out of range");
        }
        return false;
    }
    for (unsigned i = 0; i < ARRAY_SIZE(disp0_mapper_paths); i++) {
        if (!apple_modern_adt_property(dtree, disp0_mapper_paths[i],
                                       "AAPL,phandle", &value, errp) ||
            value.size != 4) {
            if (!errp || !*errp) {
                error_setg(errp, "modern disp0 DART mapper phandle must be u32");
            }
            return false;
        }
        disp0_phandles[i] = ldl_le_p(value.data);
        if (!apple_modern_adt_property(dtree, disp0_mapper_paths[i],
                                       "reg", &value, errp) ||
            value.size != 4 ||
            (disp0_streams[i] = ldl_le_p(value.data)) >= disp0_num_streams ||
            ldl_le_p(parents.data + i * 4) != disp0_phandles[i]) {
            if (!errp || !*errp) {
                error_setg(errp, "modern disp0 iommu-parent must resolve to "
                           "mapper-disp0 and mapper-disp0-piodma");
            }
            return false;
        }
    }

    DeviceState *dcp_dev = qdev_new(TYPE_APPLE_DART_T8110);
    s->dcp_mapper = APPLE_DART_T8110(dcp_dev);
    dcp_dev->id = g_strdup("modern-dcp-dart");
    object_property_add_child(OBJECT(s), "dart-dcp", OBJECT(dcp_dev));
    qdev_prop_set_uint32(dcp_dev, "mmio-size", dcp_span);
    qdev_prop_set_uint32(dcp_dev, "num-streams", dcp_num_streams);
    qdev_prop_set_uint32(dcp_dev, "va-bits", 42);
    qdev_prop_set_uint32(dcp_dev, "pa-bits", 42);
    qdev_prop_set_uint32(dcp_dev, "revision", 2);
    qdev_prop_set_bit(dcp_dev, "trace", true);
    sysbus_connect_irq(SYS_BUS_DEVICE(dcp_dev), 0,
                       qdev_get_gpio_in(s->aic, ldl_le_p(ints.data)));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dcp_dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dcp_dev), 0, dcp_base);
    s->dcp_dma_as = apple_dart_t8110_dma_as(s->dcp_mapper, dcp_stream);
    s->dcp_dart_address = dcp_base;
    s->dcp_dart_size = dcp_span;

    DeviceState *disp0_dev = qdev_new(TYPE_APPLE_DART_T8110);
    s->disp0_mapper = APPLE_DART_T8110(disp0_dev);
    disp0_dev->id = g_strdup("modern-disp0-dart");
    object_property_add_child(OBJECT(s), "dart-disp0", OBJECT(disp0_dev));
    qdev_prop_set_uint32(disp0_dev, "mmio-size", disp0_span);
    qdev_prop_set_uint32(disp0_dev, "num-streams", disp0_num_streams);
    qdev_prop_set_uint32(disp0_dev, "va-bits", 42);
    qdev_prop_set_uint32(disp0_dev, "pa-bits", 42);
    qdev_prop_set_uint32(disp0_dev, "revision", 2);
    qdev_prop_set_bit(disp0_dev, "trace", true);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(disp0_dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(disp0_dev), 0, disp0_base);
    s->disp0_dma_as = apple_dart_t8110_dma_as(s->disp0_mapper,
                                              disp0_streams[0]);
    s->disp0_dart_address = disp0_base;
    s->disp0_dart_size = disp0_span;

    warn_report("apple-modern: opt-in DCP/disp0 t8110 DARTs at 0x%" PRIx64
                "+0x%" PRIx64 " (stream %u) and 0x%" PRIx64 "+0x%" PRIx64
                " (streams %u/%u); 42-bit VA/PA and revision 2 declared",
                dcp_base, dcp_span, dcp_stream,
                disp0_base, disp0_span, disp0_streams[0], disp0_streams[1]);
    return true;
}

/*
 * Mapped BEFORE map_disp_trace for the same reason map_dcp_asc is: disp0
 * reg[4] contains the /arm-io/dcp windows, and the trace plan must skip it
 * rather than answer this peer's registers with a logging aperture's zero.
 */
static bool map_dcp_iop(AppleModernMachine *s, uint64_t uart,
                        uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernDcpIopPlan plan;
    size_t count;
    unsigned mode = 0;
    SysBusDevice *sbd;

    if ((s->dcp_attach_cbs || s->dcp_attach_trigger) &&
        (!apple_modern_dcp_iop_mode(s->dcp_iop, &mode) ||
         mode != APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED)) {
        error_setg(errp, "dcp-attach-cbs/dcp-attach-trigger need "
                   "dcp-iop=v6-resumed");
        return false;
    }
    if (s->dcp_attach_trigger && !s->dcp_attach_cbs) {
        error_setg(errp, "dcp-attach-trigger needs dcp-attach-cbs");
        return false;
    }
    if (s->dcp_attach_trigger && strcmp(s->dcp_attach_trigger, "normal-mode") &&
        strcmp(s->dcp_attach_trigger, "a453")) {
        error_setg(errp, "dcp-attach-trigger must be normal-mode or a453");
        return false;
    }
    if (s->dcp_attach_cbs &&
        !apple_modern_dcp_iop_attach_valid(s->dcp_attach_cbs, errp)) {
        return false;
    }
    if (!apple_modern_dcp_iop_mode(s->dcp_iop, &mode)) {
        error_setg(errp, "unknown dcp-iop mode '%s' (supported: %s)",
                   s->dcp_iop, APPLE_MODERN_DCP_IOP_MODE_NAMES);
        return false;
    }
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp)) {
        return false;
    }
    /*
     * flags-only maps nothing, so it must not be refused for overlapping a
     * window it will never claim (dcp-asc may legitimately own them then).
     */
    if (!apple_modern_dcp_iop_plan_build(dtree, s->components.dram_base,
            s->components.dram_size,
            apple_modern_dcp_iop_mode_has_peer(mode) ? exclusions : NULL,
            apple_modern_dcp_iop_mode_has_peer(mode) ? count : 0,
            APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, errp)) {
        return false;
    }
    if (mode == APPLE_MODERN_DCP_IOP_MODE_V6_EXPERT_START &&
        !apple_modern_dcp_iop_expert_plan_build(dtree,
            s->components.dram_base, s->components.dram_size,
            exclusions, count, &plan, errp)) {
        return false;
    }
    if (mode == APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED &&
        !apple_modern_dcp_iop_resumed_plan_build(dtree,
            s->components.dram_base, s->components.dram_size,
            exclusions, count, &plan, errp)) {
        return false;
    }
    s->dcp_iop_plan = plan;
    if (!apple_modern_dcp_iop_mode_has_peer(mode)) {
        warn_report("apple-modern: opt-in dcp-iop '%s' serves ONLY the two "
                    "declared ADT flags (pre-loaded, running) on "
                    "/arm-io/dcp/iop-dcp-nub; NO peer device is created, so "
                    "nothing answers the mailbox and no endpoint is "
                    "advertised", s->dcp_iop);
        return true;
    }
    s->dcp_iop_dev = apple_modern_dcp_iop_new(&plan, mode);
    /* The QOM child name must not collide with the board property name. */
    s->dcp_iop_dev->id = g_strdup("dcp-iop-dev");
    object_property_add_child(OBJECT(s), "dcp-iop-dev",
                              OBJECT(s->dcp_iop_dev));
    sbd = SYS_BUS_DEVICE(s->dcp_iop_dev);
    sysbus_realize_and_unref(sbd, &error_fatal);
    sysbus_mmio_map(sbd, 0, plan.wrapper_address);
    if (plan.expert_control_address) {
        sysbus_mmio_map(sbd, 1, plan.expert_control_address);
        warn_report("apple-modern: declared DCP expert-control bridge at "
                    "0x%" PRIx64 " size4 on0x%x/off0x%x, no firmware executes",
                    plan.expert_control_address, plan.expert_control_on,
                    plan.expert_control_off);
    }
    if (plan.core_address && plan.segment_address) {
        sysbus_mmio_map(sbd, 2, plan.core_address);
        sysbus_mmio_map(sbd, 3, plan.segment_address);
        warn_report("apple-modern: declared DCP core/segment windows at "
                    "0x%" PRIx64 "+0x%" PRIx64 " and 0x%" PRIx64 "+0x%" PRIx64
                    " (dual user endpoints 23/0x37 and 24/0x38)",
                    plan.core_address, plan.core_size,
                    plan.segment_address, plan.segment_size);
    }
    if (mode == APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED) {
        if (!map_dcp_dart(s, errp)) {
            return false;
        }
        apple_modern_dcp_iop_set_dma(s->dcp_iop_dev, s->dcp_dma_as,
                                     s->disp0_dma_as);
        apple_modern_dcp_iop_set_scanout(s->dcp_iop_dev,
                                         s->metadata.layout.framebuffer_physical,
                                         s->metadata.layout.framebuffer_size);
        if (s->dcp_attach_cbs) {
            apple_modern_dcp_iop_set_attach(s->dcp_iop_dev, s->dcp_attach_cbs,
                                            s->dcp_attach_trigger &&
                                            !strcmp(s->dcp_attach_trigger,
                                                    "a453"));
            warn_report("apple-modern: dcp-iop v6-resumed attach callbacks "
                        "[%s] armed, trigger %s", s->dcp_attach_cbs,
                        s->dcp_attach_trigger ? s->dcp_attach_trigger :
                                                "normal-mode");
        }
    }
    /*
     * Positional IRQ mapping, in ADT "interrupts" order, exactly as t8030
     * wires SMC, SIO and ANS.  The four lines are the AP mailbox's
     * (IOP_NONEMPTY, IOP_EMPTY, AP_NONEMPTY, AP_EMPTY); which ADT line is
     * which is DECLARED by that convention, not attested.
     */
    for (unsigned i = 0; i < APPLE_MODERN_DCP_IOP_IRQS; i++) {
        if (plan.interrupts[i] >= s->aic_num_irqs) {
            error_setg(errp, "/arm-io/dcp interrupt %u (%u) is outside the "
                       "modelled AIC's %u lines", i, plan.interrupts[i],
                       s->aic_num_irqs);
            return false;
        }
        sysbus_connect_irq(sbd, i, qdev_get_gpio_in(s->aic,
                                                    plan.interrupts[i]));
    }
    s->dcp_iop_mapped = true;
    warn_report("apple-modern: opt-in dcp-iop '%s': an RTKit peer on "
                "/arm-io/dcp reg[0] 0x%" PRIx64 "+0x%" PRIx64 " (register "
                "file %s), role \"%s\", advertising ONE user endpoint "
                "(user-relative %u, raw %u) so RTBuddy should publish the nub "
                "\"%s\" that AppleDCPLinkServiceSoC matches. DECLARED: this "
                "loader places NO DCP firmware and publishes no carveout, so "
                "the handshake is answered by this model; no DCP message "
                "semantics are implemented",
                s->dcp_iop, plan.wrapper_address, plan.wrapper_size,
                mode == APPLE_MODERN_DCP_IOP_MODE_V4 ? "v4" : "v6", plan.role,
                plan.endpoint_user, plan.endpoint_raw, plan.nub_name);
    return true;
}
static bool map_disp_trace(AppleModernMachine *s, uint64_t uart,
                           uint64_t uart_span, Error **errp)
{
    AppleModernBlob dtree = {s->metadata.dtree, s->metadata.dtree_size};
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    AppleModernDispTracePlan plan;
    size_t count;
    unsigned region = 0;
    if (!pmgr_exclusions(s, uart, uart_span, exclusions, &count, errp) ||
        !apple_modern_disp_trace_plan_build(dtree, s->components.dram_base,
            s->components.dram_size, exclusions, count, &plan, errp)) {
        return false;
    }
    DeviceState *dev = apple_modern_disp_trace_new(&plan);
    dev->id = g_strdup("disp-trace");
    object_property_add_child(OBJECT(s), "disp-trace", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    for (unsigned i = 0; i < plan.count; i++) {
        if (plan.windows[i].status == APPLE_MODERN_DISP_TRACE_MAPPED) {
            sysbus_mmio_map(SYS_BUS_DEVICE(dev), region++,
                            plan.windows[i].physical_address);
        }
    }
    s->disp_trace_plan = plan;
    for (unsigned i = 0; i < plan.count; i++) {
        const AppleModernDispTraceWindow *w = &plan.windows[i];
        static const char *const why[] = {"mapped", "skipped: in DRAM",
            "skipped: another device", "skipped: inside an earlier window",
            "skipped: partly overlaps an earlier window"};
        warn_report("apple-modern: disp-trace %s reg[%u] 0x%" PRIx64 "+0x%"
                    PRIx64 " %s", apple_modern_disp_trace_node_name(w->node),
                    w->reg_index, w->physical_address, w->size,
                    w->status < 5 ? why[w->status] : "?");
    }
    warn_report("apple-modern: opt-in disp0 bind probe '%s': %u of %u display "
                "register windows mapped as LOGGING APERTURES (reads answer "
                "zero, writes are discarded, nothing is modelled); ADT "
                "\"compatible\" restored from the stock tree so AppleCLCD2 "
                "can match", s->disp0_probe, plan.mapped, plan.count);
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
        qdev_prop_set_bit(s->aic, "record-irq-config",
                          s->aic_record_irq_config);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(s->aic), &error_fatal);
        sysbus_mmio_map(SYS_BUS_DEVICE(s->aic), 0, base);
        s->aic_num_irqs = num_irqs;
        warn_report("apple-modern: AIC%u enabled, %u IRQs, config at 0x%x "
                    "(opt-in modern-aic)", revision, num_irqs, extint);
        if (s->aic_record_irq_config) {
            warn_report("apple-modern: AIC records IRQ_CFG words and delivers "
                        "every interrupt to CPU0 whatever target is written "
                        "(opt-in aic-record-irq-config; delay groups are not "
                        "modelled)");
        }
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

/*
 * gfx-asc: the GPU's Apple System Coprocessor mailbox.
 *
 * Milestone A of the GPU bring-up. iOS 27's CoreAnimation render server is
 * Metal-only on the display path: both server accessors in QuartzCore
 * (AccelServer 0x184415838, VirtualServer 0x184629958) call
 * MTLCreateSystemDefaultDevice and, on NULL, return a still-NULL renderer with
 * no software fallback. Before that can ever succeed QuartzCore must find an
 * IOKit service matching "AGXAccelerator" -- it does
 * IOServiceMatching("AGXAccelerator") + IOServiceGetMatchingService and gives
 * up on zero. That service is published by com.apple.AGXG17P, which cannot
 * match while /arm-io/gfx-asc has no coprocessor behind it: the stock ADT
 * describes the node (device_type 'gfx-asc', role 'GFX', iop-version 1,
 * reg window 0 = 0x272600000/0x88000, four interrupts) but this board mapped
 * nothing there, so the ASCWrap registers read as zeros through the arm-io
 * catch-all and RTBuddy never comes up.
 *
 * This creates the wrapper exactly as map_sep_mailbox() does for the SEP:
 * window 0 only, a bare AppleRTKit so the standard EP0 management handshake
 * (EPMAP/rollcall/power) is answered, and the ADT's four interrupt lines wired
 * positionally to the AIC. rtkit.c NULL-guards every ops callback, so no
 * endpoint handlers are needed for the driver to begin its handshake.
 *
 * The real G17P firmware is on hand and unencrypted, so the next step is to
 * trace what the guest driver asks for rather than guess:
 *   evidence/firmware-20261009/GFX/armfw_g17p.im4p -> IM4P 'gfxf', no KBAG,
 *   5770288 bytes, container 'rkosftab' of five Mach-O arm64e preload images
 *   (a000/b000/b100 = variant g17p, a010/b010 = g17a),
 *   RTKit_release-3514.0.15.release, declaring the channels
 *   gfx_msgs / gfx_ints / gfx_iop_msgs / gfx_iop_ints.
 * Opt-in via -M apple-modern,gfx-asc=on; it stays off by default because the
 * register layout below is the same declared ascwrap-v6 reading the SEP
 * mailbox uses, not Apple-documented, and no GPU hardware is modelled behind
 * it (so no rendering can result from this alone).
 */
/*
 * gfx-asc reg[1]: the ASCWrap CORE register window, eight bytes.
 *
 * Attested gate (AGX Milestone-A RE, BootKC a36b9241): AppleASCWrapV6 (vtable
 * slot +0x6d8) reads 64 bits at offset 0 of this window and REQUIRE-panics
 * "ASC firmware must be loaded by iBoot" (AppleASCWrapCommon.cpp:151) when
 * BIT 0 IS CLEAR -- gate at 0xfffffff00856e31c:
 *     ldr w8,[this,#0x188] ; ldr x9,[this,#0x198] ; ldr x8,[x9+x8]
 *     tbz w8,#0 -> 0xfffffff00856e33c -> thunk 0xfffffff00856f588
 * Unmapped, bit 0 reads 0 and the panic is certain. This is the same shape the
 * project already attested for /arm-io/dcp in modern-dcp-asc.h, except the DCP
 * core window is 0x4000 bytes while gfx-asc's is a single 64-bit register
 * (real-device IODeviceMemory: address 19361234944, length 8).
 *
 * So bit 0 is answered as 1: a DECLARED claim that the bootloader loaded the
 * ASC firmware. Nothing is actually placed -- exactly the declaration
 * dcp-iop already makes for the DCP -- so this clears the wrapper gate only;
 * RTBuddy's own _attemptFirmwareLoad (RTBuddy.cpp:346) still needs real
 * firmware bytes and a carveout.
 */
#define APPLE_MODERN_GFX_CORE_LOADED 1

/*
 * The GPU coprocessor's user endpoints.
 *
 * The real a000 firmware declares its channels in its own __DATA descriptor
 * tables (mgmt block at firmware VA 0xfffffc000006f4c0, iop block at
 * 0xfffffc000005b540) as: management = 0x01, crashlog = 0x20,
 * gfx_msgs = 0x21 (paired with gfx_ints), an unnamed 0x22, and
 * gfx_iop_msgs = 0x23 (paired with gfx_iop_ints).
 *
 * rtkit.c numbers USER endpoints relatively: EP_USER_START is 32 (0x20) and
 * apple_rtkit_register_user_ep()/send_user_msg() add it (rtkit.h:89-92,
 * rtkit.c:142-149). So the raw channel numbers map to user-relative
 * 0x21 - 0x20 = 1 and 0x23 - 0x20 = 3.
 *
 * MEASURED (v71): with no user endpoint registered at all, the GFX handshake
 * still completes -- iop_start, HELLO, HELLO_ACK (protocol 0xc), EPMAP,
 * rollcall_finished -- and then negotiates only raw 0x20, so the GPU's own
 * channels are never brought up. Registering these two is what lets RTBuddy
 * reach them. Messages are logged and otherwise unanswered: no AGX command
 * semantics are implemented, and none can be until the firmware's initdata
 * handshake (Asahi InitMsg type 0x81) is understood.
 */
#define APPLE_MODERN_GFX_EP_MSGS_USER 1     /* raw 0x21, gfx_msgs */
#define APPLE_MODERN_GFX_EP_IOP_MSGS_USER 3 /* raw 0x23, gfx_iop_msgs */

static void gfx_ep_handle_message(void *opaque, uint8_t ep, uint64_t msg)
{
    qemu_log_mask(LOG_UNIMP, "GFX-EP raw 0x%02x message 0x%016" PRIx64
                  " (logged, unanswered: no AGX semantics are modelled)\n",
                  ep, msg);
}

static uint64_t gfx_core_read(void *opaque, hwaddr offset, unsigned size)
{
    uint64_t value = (offset == 0) ? APPLE_MODERN_GFX_CORE_LOADED : 0;

    qemu_log_mask(LOG_UNIMP, "GFX-CORE read  +0x%02" PRIx64 " size %u -> 0x%"
                  PRIx64 "\n", (uint64_t)offset, size, value);
    return value;
}

static void gfx_core_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "GFX-CORE write +0x%02" PRIx64 " size %u value 0x%"
                  PRIx64 "\n", (uint64_t)offset, size, value);
}

static const MemoryRegionOps gfx_core_ops = {
    .read = gfx_core_read,
    .write = gfx_core_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

static bool map_gfx_core(AppleModernMachine *s, const AppleModernBlob *reg,
                         Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    uint64_t offset = ldq_le_p(reg->data + 16);
    uint64_t size = ldq_le_p(reg->data + 24);
    uint64_t base;

    if (!size || size > 0x1000) {
        error_setg(errp, "modern gfx-asc core window is out of range");
        return false;
    }
    if (!arm_io_translate(dtree, offset, size, &base, errp)) {
        return false;
    }
    memory_region_init_io(&s->gfx_core_mr, NULL, &gfx_core_ops, s,
                          "apple-modern.gfx-core", size);
    memory_region_add_subregion(get_system_memory(), base, &s->gfx_core_mr);
    warn_report("apple-modern: gfx-asc core window at 0x%" PRIx64 " size 0x%"
                PRIx64 ", bit 0 of +0 DECLARED 1 so AppleASCWrapV6 does not "
                "panic \"ASC firmware must be loaded by iBoot\"; no firmware "
                "is actually placed", base, size);
    return true;
}

static bool map_gfx_mailbox(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob reg, ints, compatible;
    uint64_t offset, size, base;

    if (!apple_modern_adt_property(dtree, "/arm-io/gfx-asc", "reg", &reg,
                                   errp)) {
        return false;
    }
    if (reg.size != 32) {
        error_setg(errp, "unsupported modern gfx-asc reg schema");
        return false;
    }
    /* Window 0 only, matching the SEP treatment of the same wrapper. */
    offset = ldq_le_p(reg.data);
    size = ldq_le_p(reg.data + 8);
    if (size < 0x10000 || size > 0x400000) {
        error_setg(errp, "modern gfx-asc register span is out of range");
        return false;
    }
    if (!arm_io_translate(dtree, offset, size, &base, errp)) {
        return false;
    }
    /*
     * Accept a missing compatible for the same reason the SEP does: Darwin's
     * device-tree fixup strips it, and adt-compat-restore=...+gfx is what puts
     * "iop,ascwrap-v6" back.
     */
    if (apple_modern_adt_property(dtree, "/arm-io/gfx-asc", "compatible",
                                  &compatible, NULL)) {
        if (compatible.size < sizeof("iop,ascwrap-v6") ||
            memcmp(compatible.data, "iop,ascwrap-v6",
                   sizeof("iop,ascwrap-v6"))) {
            error_setg(errp, "unsupported modern gfx-asc wrapper (expected "
                       "iop,ascwrap-v6; pass adt-compat-restore=...+gfx)");
            return false;
        }
    } else {
        warn_report("apple-modern: /arm-io/gfx-asc has no compatible string; "
                    "assuming iop,ascwrap-v6 (pass adt-compat-restore=...+gfx "
                    "to restore it)");
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/gfx-asc", "interrupts",
                                   &ints, errp)) {
        return false;
    }
    if (ints.size != 16) {
        error_setg(errp, "modern gfx-asc names %zu interrupt bytes, expected "
                   "16", (size_t)ints.size);
        return false;
    }
    if (!s->aic) {
        error_setg(errp, "gfx-asc needs modern-aic: without a controller no "
                   "doorbell can be delivered");
        return false;
    }

    s->gfx_mbox = DEVICE(apple_rtkit_new(NULL, "GFX", size, APPLE_A7IOP_V6,
                                         NULL));
    /*
     * Advertise the firmware's two message channels so the rollcall offers
     * more than crashlog; see the endpoint note above.
     */
    apple_rtkit_register_user_ep(APPLE_RTKIT(s->gfx_mbox),
                                 APPLE_MODERN_GFX_EP_MSGS_USER, s,
                                 gfx_ep_handle_message);
    apple_rtkit_register_user_ep(APPLE_RTKIT(s->gfx_mbox),
                                 APPLE_MODERN_GFX_EP_IOP_MSGS_USER, s,
                                 gfx_ep_handle_message);

    /*
     * Positional, as for the SEP: index i -> interrupts[i]. The ADT carries no
     * interrupt-names on any node in this tree, so which of the four lines the
     * GPU driver actually registers is still to be measured.
     */
    for (unsigned i = 0; i < APPLE_A7IOP_IRQ_MAX; i++) {
        uint32_t line = ldl_le_p(ints.data + i * 4);

        if (line >= s->aic_num_irqs) {
            error_setg(errp, "modern gfx-asc interrupt %u is outside the %u "
                       "controller inputs", line, s->aic_num_irqs);
            return false;
        }
        sysbus_connect_irq(SYS_BUS_DEVICE(s->gfx_mbox), i,
                           qdev_get_gpio_in(s->aic, line));
    }
    /* Connect before realize; see the note in map_sep_mailbox(). */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->gfx_mbox), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->gfx_mbox), 0, base);
    /*
     * reg[1] is the ASCWrap core register and its bit 0 is the wrapper's
     * "firmware loaded by iBoot" gate; without it AppleASCWrapV6 panics before
     * RTBuddy is ever reached.
     */
    if (reg.size >= 32 && !map_gfx_core(s, &reg, errp)) {
        return false;
    }
    warn_report("apple-modern: gfx-asc RTKit mailbox at 0x%" PRIx64 " size 0x%"
                PRIx64 ", AIC inputs %u/%u/%u/%u (opt-in; no GPU hardware is "
                "modelled behind it, so this cannot render -- it exists so "
                "AGXG17P can probe and be traced)",
                base, size, ldl_le_p(ints.data), ldl_le_p(ints.data + 4),
                ldl_le_p(ints.data + 8), ldl_le_p(ints.data + 12));
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
 * Observation apertures over the two /arm-io/sgx register windows.
 *
 * The node restored by sgx=on is what AGXAcceleratorG17P matches, and nothing
 * in this board models a GPU behind it: reads return zero, writes are
 * discarded and every access is logged under -d unimp. That is deliberate for
 * Milestone A -- the point is to find out what the accelerator touches first,
 * and reads of zero are the behaviour the unmapped address range would have
 * given anyway, minus the external abort an unassigned access would raise.
 *
 * Stock reg is two windows (/arm-io offsets, translated through the bus
 * ranges): 0x270000000 + 0x4000000 -> 0x480000000, and 0x270d00000 + 0x12c000
 * -> 0x480d00000. Both are published at a NEGATIVE priority so any real device
 * mapped inside them keeps precedence -- modern-pmgr-storage, for one,
 * declares a power-state block at 0x481000000, inside window 0.
 */
typedef struct AppleModernSGXTrace {
    uint64_t base;
    unsigned index;
    bool answer;
} AppleModernSGXTrace;

/*
 * Opt-in probe answer for the GPU register aperture (gpu-trace-answer=on).
 *
 * MEASURED (v81): with the aperture reading all zeroes, AGXG17P probes exactly
 * seven registers and then stops, publishing no accelerator -- window 1
 * offsets 0x4000, 0x4010, 0x4014, 0x4018, 0x401c, 0x4008, then 0x101500. That
 * is the shape of an ID/capability register reading zero and the driver
 * declining the hardware, so the probe is gated on values this model controls.
 *
 * This answers those offsets non-zero so the NEXT gate can be observed. The
 * values are a DECLARED GUESS, not Apple-documented and not measured from
 * hardware: the only corroborated facts are the G17P configuration the
 * public agx-re corpus reports (num_cores 6, core_mask 61 = 0x3d, usc_gen 3,
 * gpu_gen 17 = 0x11, gpu_var "P", is_sksm 1), and it is NOT established that
 * these registers carry those fields. The point is purely to distinguish
 * "zero means absent" from "the driver wants specific values"; whatever it
 * reads next is the real information. Default off so no run silently depends
 * on invented register content.
 */
static uint64_t sgx_trace_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleModernSGXTrace *t = opaque;
    uint64_t value = 0;

    if (t->answer && t->index == 1) {
        switch (offset) {
        /*
         * RE-DERIVED, not a guess. The reader at linked 0xfffffff0084cbe3c
         * fetches this register via the helper 0xfffffff0084f6d4c (args:
         * this, register offset; the six calls pass 0xd04000, +0x10, +0x14,
         * +0x18, +0x1c, +0x08 -- exactly the offsets observed on the wire),
         * then branches on its TOP BYTE:
         *     lsr w8, w23, #0x18
         *     cmp w8, #0xa ; b.eq 0xfffffff0084cbf58   (accepted)
         *     cmp w8, #8   ; b.ne 0xfffffff0084cbf84   (-> stp xzr,xzr,[x19,#0x10],
         *                                                 fields stay 0, probe bails)
         * On the 0xa path it then needs byte 2 nonzero:
         *     ubfx w8, w23, #0x10, #8 ; cbz w8 -> 0xfffffff0084cc36c
         * So: top byte 0xa (or 8) and byte 2 nonzero. 0x0a010000 satisfies both.
         * The field is evidently a GPU architecture/generation code; which of 8
         * or 0xa is correct for G17P is NOT established -- this run tests 0xa.
         */
        case 0x4000: value = 0x0a020000; break;   /* byte2 MUST be 2 */
        case 0x4008: value = 0x11; break;       /* gpu_gen 17, if it is that */
        /*
         * +0x30 and +0x44 are computed from THIS register (x21), and both must
         * be non-zero or the caller bails:
         *     w9 = ((x21>>8)&0xff) * ((x21>>16)&0xf)      -> stored at +0x64
         *     +0x30 = +0x44 = w9 * (x21 & 0xff)
         * 0x00010106 -> w9 = 1*1 = 1, field = 1*6 = 6 (non-zero). The low byte
         * is plausibly a core count (G17P has 6 per the agx-re corpus); the
         * two upper fields are set to 1 purely to make the product non-zero.
         */
        case 0x4010: value = 0x00010106; break;
        case 0x4014: value = 0x3d; break;       /* core_mask 61 candidate */
        case 0x4018: value = 0x3; break;        /* usc_gen candidate */
        case 0x401c: value = 0x1; break;
        case 0x101500: value = 0x1; break;
        default: value = 0; break;
        }
    }
    /*
     * Log the GUEST PC/LR of the accessor. v82 proved the seven probed
     * register VALUES are not the gate (answering them non-zero produced a
     * byte-identical run), and no AGX kext ever logs anything, so the open
     * question is WHO is reading: AGXAcceleratorG17P, or some other driver
     * touching the aperture. The guest PC answers that directly and costs
     * nothing -- map it against the kext load addresses in the same boot
     * (e.g. the RTBuddy range com.apple.driver.RTBuddy@0xfffffff02a886cd0
     * that appears in serial).
     */
    if (current_cpu != NULL) {
        CPUARMState *env = &ARM_CPU(current_cpu)->env;

        qemu_log_mask(LOG_UNIMP, "SGX-TRACE win%u read  0x%" PRIx64 " +0x%07"
                      PRIx64 " size %u -> 0x%" PRIx64 "  [guest pc 0x%016"
                      PRIx64 " lr 0x%016" PRIx64 "]\n", t->index, t->base,
                      (uint64_t)offset, size, value, (uint64_t)env->pc,
                      (uint64_t)env->xregs[30]);
    } else {
        qemu_log_mask(LOG_UNIMP, "SGX-TRACE win%u read  0x%" PRIx64 " +0x%07"
                      PRIx64 " size %u -> 0x%" PRIx64 "  [no cpu context]\n",
                      t->index, t->base, (uint64_t)offset, size, value);
    }
    return value;
}

static void sgx_trace_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size)
{
    AppleModernSGXTrace *t = opaque;

    qemu_log_mask(LOG_UNIMP, "SGX-TRACE win%u write 0x%" PRIx64 " +0x%07"
                  PRIx64 " size %u value 0x%" PRIx64 "\n", t->index, t->base,
                  (uint64_t)offset, size, value);
}

static const MemoryRegionOps sgx_trace_ops = {
    .read = sgx_trace_read,
    .write = sgx_trace_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

static bool map_sgx_trace(AppleModernMachine *s, Error **errp)
{
    AppleModernBlob dtree = { s->metadata.dtree, s->metadata.dtree_size };
    AppleModernBlob reg;
    Error *local = NULL;

    /*
     * The served tree is the one the node was appended to -- but the GPU node
     * is not always called "sgx". SPTM finds the GPU by PATH and panics in its
     * UAT bootstrap when a node literally at /arm-io/sgx lacks iBoot's GPU
     * handoff properties, while AGXAcceleratorG17P finds it by PROPERTY VALUE
     * (IONameMatch gpu,t8140 on an AppleARMIODevice) and does not care about
     * the name. Serving the same 26 properties as /arm-io/gpu0 therefore gets
     * the accelerator to probe with SPTM's GPU path skipped entirely
     * (measured: a node named sgx gives 0 bytes of serial, named gpu0 the
     * guest boots). Accept either name so the trace aperture follows the node.
     */
    if (!apple_modern_adt_property(dtree, "/arm-io/sgx", "reg", &reg,
                                   &local)) {
        error_free(local);
        local = NULL;
        if (!apple_modern_adt_property(dtree, "/arm-io/gpu0", "reg", &reg,
                                       &local)) {
            error_propagate(errp, local);
            return false;
        }
    }
    if (reg.size != 32) {
        error_setg(errp, "unsupported modern sgx reg schema");
        return false;
    }
    for (size_t i = 0; i + 16 <= reg.size; i += 16) {
        uint64_t offset = ldq_le_p(reg.data + i);
        uint64_t size = ldq_le_p(reg.data + i + 8);
        AppleModernSGXTrace *trace;
        uint64_t base;
        char name[32];

        if (s->sgx_trace_count >= ARRAY_SIZE(s->sgx_trace_mr)) {
            break;
        }
        if (!size || size > 0x8000000) {
            error_setg(errp, "modern sgx register window is out of range");
            return false;
        }
        if (!arm_io_translate(dtree, offset, size, &base, errp)) {
            return false;
        }
        trace = g_new0(AppleModernSGXTrace, 1);
        trace->base = base;
        trace->index = s->sgx_trace_count;
        trace->answer = s->gpu_trace_answer;
        snprintf(name, sizeof(name), "apple-modern.sgx-trace%u",
                 s->sgx_trace_count);
        memory_region_init_io(&s->sgx_trace_mr[s->sgx_trace_count], NULL,
                              &sgx_trace_ops, trace, name, size);
        memory_region_add_subregion_overlap(get_system_memory(), base,
                                            &s->sgx_trace_mr[s->sgx_trace_count],
                                            -1);
        warn_report("apple-modern: sgx trace window %u at 0x%" PRIx64
                    " size 0x%" PRIx64 " (observation only, not a device: no "
                    "GPU is modelled, so nothing can render)",
                    s->sgx_trace_count, base, size);
        s->sgx_trace_count++;
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

/*
 * Apply the selected declared image-patch set to the board's PRIVATE in-memory
 * image copies. Never touches a file: it snapshots each source file's stat
 * before patching and re-stats afterwards, failing if any changed.  That is a
 * cheap TRIPWIRE on size and timestamps, not a cryptographic seal: a same-size,
 * timestamp-preserving overwrite would pass it.  The real guarantee is
 * structural - the facility only ever writes the board's private in-memory copy
 * and never opens a distribution file for writing - and the whole-machine gate's
 * SHA-256 before/after comparison is the authoritative check.  The
 * applied list is recorded in s->image_patch_result and each patch is
 * announced. Returns false on any refusal, leaving the buffers untouched.
 */
static const AppleModernImage patchable_images[] = {
    APPLE_MODERN_BOOTKC, APPLE_MODERN_SPTM, APPLE_MODERN_TXM,
    APPLE_MODERN_TRUSTCACHE, APPLE_MODERN_RAMDISK,
};

/* AppleModernImage -> this board's asset slot. Indexed only by the values in
 * patchable_images above, so there is no reachable out-of-range branch. */
static const enum ModernAsset image_asset_map[] = {
    [APPLE_MODERN_BOOTKC] = ASSET_BOOTKC,
    [APPLE_MODERN_SPTM] = ASSET_SPTM,
    [APPLE_MODERN_TXM] = ASSET_TXM,
    [APPLE_MODERN_TRUSTCACHE] = ASSET_TC,
    [APPLE_MODERN_RAMDISK] = ASSET_RAMDISK,
};

static bool apply_image_patches(AppleModernMachine *s, Error **errp)
{
    const AppleModernImagePatchSet *set =
        apple_modern_image_patch_set(s->image_patches);
    struct stat before[ASSET_COUNT];
    bool have_before[ASSET_COUNT] = {0};

    if (!set) {
        error_setg(errp, "unknown image-patches set '%s' (supported: %s)",
                   s->image_patches, apple_modern_image_patch_set_names());
        return false;
    }
    /* Snapshot every present asset file so we can prove none is written. */
    for (size_t i = 0; i < ASSET_COUNT; i++) {
        if (s->paths[i] && !stat(s->paths[i], &before[i])) {
            have_before[i] = true;
        }
    }
    for (size_t k = 0; k < ARRAY_SIZE(patchable_images); k++) {
        AppleModernImage image = patchable_images[k];
        enum ModernAsset slot = image_asset_map[image];

        if (!s->blobs[slot].data) {
            continue; /* Optional image (e.g. no ramdisk) absent. */
        }
        if (!apple_modern_image_patch_apply_image(
                set, image, (uint8_t *)s->blobs[slot].data,
                s->blobs[slot].size, &s->image_patch_result, errp)) {
            return false;
        }
    }
    /* Re-verify the on-disk inputs are byte-for-byte untouched. */
    for (size_t i = 0; i < ASSET_COUNT; i++) {
        struct stat after;
        if (!have_before[i]) {
            continue;
        }
        if (stat(s->paths[i], &after) || after.st_size != before[i].st_size ||
            after.st_mtim.tv_sec != before[i].st_mtim.tv_sec ||
            after.st_mtim.tv_nsec != before[i].st_mtim.tv_nsec ||
            after.st_ctim.tv_sec != before[i].st_ctim.tv_sec ||
            after.st_ctim.tv_nsec != before[i].st_ctim.tv_nsec) {
            error_setg(errp, "image-patch: source file changed on disk: %s",
                       s->paths[i]);
            return false;
        }
    }
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
    if (s->large_ramdisk && !s->paths[ASSET_RAMDISK]) {
        error_report("apple-modern: large-ramdisk needs a ramdisk asset");
        exit(EXIT_FAILURE);
    }
    /*
     * The pipe owns the same framebuffer reservation and the same QEMU
     * console as the fixed boot scanout, so exactly one of them may run.
     */
    if (s->disp0_pipe && s->boot_display) {
        error_report("apple-modern: disp0-pipe replaces boot-display; "
                     "enable one, not both");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < ASSET_COUNT; i++) {
        if (i == ASSET_RAMDISK && (!s->paths[i] || s->large_ramdisk)) {
            continue;
        }
        if (i == ASSET_CRYPTEX_TC && !s->paths[i]) {
            continue; /* Default: a single-module trust-cache catalog. */
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
        .cryptex_trustcache = s->blobs[ASSET_CRYPTEX_TC],
        .large_ramdisk = s->large_ramdisk,
        .dram_base = UINT64_C(1) << 40, .dram_size = machine->ram_size,
        .framebuffer_width = (s->boot_display || s->disp0_pipe) ?
                                 s->display_width : 0,
        .framebuffer_height = (s->boot_display || s->disp0_pipe) ?
                                  s->display_height : 0,
        .framebuffer_stride = (s->boot_display || s->disp0_pipe) ?
                                  s->display_stride : 0,
        .trustcache_v2 = s->trustcache_v2,
    };
    if (s->ramdisk_patches && !s->large_ramdisk) {
        error_report("apple-modern: ramdisk-patches needs large-ramdisk=on");
        exit(EXIT_FAILURE);
    }
    if (s->large_ramdisk) {
        if (!apple_modern_large_ramdisk_map(s->paths[ASSET_RAMDISK],
                                            &s->large_ramdisk_file, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        if (s->ramdisk_patches) {
            unsigned applied;

            if (!apple_modern_large_ramdisk_patch(&s->large_ramdisk_file,
                                                  s->ramdisk_patches, &applied,
                                                  &error)) {
                error_report_err(error);
                exit(EXIT_FAILURE);
            }
            warn_report("apple-modern: opt-in ramdisk-patches applied %u "
                        "declared in-memory edit(s) from %s to the private "
                        "ramdisk mapping (the image file is unchanged)",
                        applied, s->ramdisk_patches);
        }
        s->components.ramdisk = (AppleModernBlob){
            s->large_ramdisk_file.host, s->large_ramdisk_file.file_size };
        warn_report("apple-modern: opt-in large-ramdisk maps %" PRIu64
                    " bytes of %s read-only and privately (the file is never "
                    "written; guest stores become host copy-on-write pages, "
                    "and the mapping is lazy, so the file must stay "
                    "unchanged while the guest runs)",
                    s->large_ramdisk_file.file_size, s->paths[ASSET_RAMDISK]);
    }
    metadata_input.components = &s->components;
    metadata_input.command_line = s->boot_command_line;
    metadata_input.command_line_length = s->boot_command_line ?
                                         strlen(s->boot_command_line) : 0;
    metadata_input.has_mte = s->mte;
    /*
     * Opt-in GPU/UAT carveout. 4 MiB covers the four regions SPTM's unified
     * address translator asks for (shared/ASC, TTBR1 shared L2, TTBAT, GPU
     * handoff) with room to spare; see gfx_carveout_size in
     * modern-boot-metadata.h. The resulting base is reported below so the ADT
     * handoff properties can point at it.
     */
    metadata_input.gfx_carveout_size = s->gfx_carveout ?
                                           APPLE_MODERN_FRAMEBUFFER_ALIGNMENT * 2 : 0;
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
    if (s->aic_record_irq_config && !s->modern_aic) {
        error_report("apple-modern: aic-record-irq-config needs "
                     "modern-aic=on; otherwise there is no controller to "
                     "record IRQ_CFG words");
        exit(EXIT_FAILURE);
    }
    if (s->disp0_probe) {
        size_t disp_count = 0;
        const AppleModernAdtOverride *disp =
            apple_modern_disp_probe_profile(s->disp0_probe, &disp_count);
        if (!disp) {
            error_report("apple-modern: unknown disp0-probe arm '%s' "
                         "(supported: %s)", s->disp0_probe,
                         APPLE_MODERN_DISP_PROBE_NAMES);
            exit(EXIT_FAILURE);
        }
        if (apple_modern_disp_probe_supplies_dart_id(s->disp0_probe) &&
            s->adt_dart_ids) {
            error_report("apple-modern: disp0-probe='%s' serves its own "
                         "declared dart-id and cannot be combined with "
                         "adt-dart-ids=on", s->disp0_probe);
            exit(EXIT_FAILURE);
        }
        for (size_t i = 0; i < disp_count; i++) {
            if (override_count >= APPLE_MODERN_MAX_ADT_OVERRIDES) {
                error_report("apple-modern: too many ADT overrides");
                exit(EXIT_FAILURE);
            }
            overrides[override_count++] = disp[i];
        }
        warn_report("apple-modern: disp0-probe '%s' restores %zu declared ADT "
                    "property values on the display nodes (stock bytes; the "
                    "distribution tree file is never written)",
                    s->disp0_probe, disp_count);
    }
    if (s->modern_smc_buttons && !s->modern_smc) {
        error_report("modern-smc-buttons needs modern-smc=on");
        exit(EXIT_FAILURE);
    }
    if (s->modern_smc) {
        size_t count = 0;
        const AppleModernAdtOverride *flags = apple_modern_smc_overrides(&count);
        if (!s->modern_aic) {
            error_report("modern-smc needs modern-aic=on");
            exit(EXIT_FAILURE);
        }
        if (override_count > APPLE_MODERN_MAX_ADT_OVERRIDES ||
            count > APPLE_MODERN_MAX_ADT_OVERRIDES - override_count) {
            error_report("modern-smc exceeds ADT override capacity");
            exit(EXIT_FAILURE);
        }
        for (size_t i = 0; i < count; i++) {
            overrides[override_count++] = flags[i];
        }
    }
    if (s->adt_compat_restore) {
        Error *groups_error = NULL;
        size_t before = override_count;

        /*
         * w14-compatsweep. Restore the byte-exact stock "compatible" on a named
         * group of nodes the served Darwin-derived tree strips it from. Nothing
         * is removed, no distribution file is written, and the generator proves
         * the groups are node-disjoint from each other and from the display
         * nodes disp0-probe owns, so the two options cannot collide.
         */
        if (!apple_modern_compat_groups_resolve(s->adt_compat_restore,
                                                overrides, &override_count,
                                                APPLE_MODERN_MAX_ADT_OVERRIDES,
                                                &groups_error)) {
            error_report_err(groups_error);
            exit(EXIT_FAILURE);
        }
        if (apple_modern_compat_groups_supply_dart_id(s->adt_compat_restore) &&
            s->adt_dart_ids) {
            error_report("apple-modern: adt-compat-restore='%s' serves its own "
                         "declared dart-id and cannot be combined with "
                         "adt-dart-ids=on", s->adt_compat_restore);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: adt-compat-restore '%s' restores %zu "
                    "declared ADT property values (stock compatible bytes plus "
                    "any declared dart-id; the distribution tree file is never "
                    "written)", s->adt_compat_restore,
                    override_count - before);
    }
    if (s->dcp_iop) {
        unsigned dcp_iop_mode = 0;
        if (!apple_modern_dcp_iop_mode(s->dcp_iop, &dcp_iop_mode)) {
            error_report("apple-modern: unknown dcp-iop mode '%s' "
                         "(supported: %s)", s->dcp_iop,
                         APPLE_MODERN_DCP_IOP_MODE_NAMES);
            exit(EXIT_FAILURE);
        }
        /*
         * Both options own /arm-io/dcp reg[0]: dcp-asc as a recording
         * aperture with an EMPTY mailbox and no peer, dcp-iop as a real RTKit
         * peer.  Mapping both would put two devices on the same bytes.
         */
        if (s->dcp_asc && apple_modern_dcp_iop_mode_has_peer(dcp_iop_mode)) {
            error_report("apple-modern: dcp-iop='%s' and dcp-asc both own the "
                         "/arm-io/dcp wrapper window; enable one, not both "
                         "(dcp-iop=flags-only creates no device and may be "
                         "combined with dcp-asc)", s->dcp_iop);
            exit(EXIT_FAILURE);
        }
        /*
         * A peer that cannot deliver its mailbox interrupt is dead code: the
         * RTKit HELLO would sit in the queue and XNU would never read it,
         * because without modern-aic the AIC window is plain RAM and no
         * interrupt is delivered at all (see map_aic).
         */
        if (apple_modern_dcp_iop_mode_has_peer(dcp_iop_mode) &&
            !s->modern_aic) {
            error_report("apple-modern: dcp-iop='%s' needs modern-aic=on; "
                         "without a controller the RTKit mailbox interrupt is "
                         "never delivered and the peer can never be read",
                         s->dcp_iop);
            exit(EXIT_FAILURE);
        }
        if (apple_modern_dcp_iop_mode_has_flags(dcp_iop_mode)) {
            size_t flag_count = 0;
            const AppleModernAdtOverride *flags =
                apple_modern_dcp_iop_overrides(&flag_count);
            for (size_t i = 0; i < flag_count; i++) {
                if (override_count >= APPLE_MODERN_MAX_ADT_OVERRIDES) {
                    error_report("apple-modern: too many ADT overrides");
                    exit(EXIT_FAILURE);
                }
                overrides[override_count++] = flags[i];
            }
            warn_report("apple-modern: dcp-iop '%s' serves %zu DECLARED ADT "
                        "flags on /arm-io/dcp/iop-dcp-nub (pre-loaded = 1, "
                        "running = 1). They are NOT in the stock tree: they "
                        "claim iBoot already loaded and started the DCP, "
                        "which this loader does not do. All five in-tree "
                        "RTKit devices set the same pair on their own nub",
                        s->dcp_iop, flag_count);
        }
        if (apple_modern_dcp_iop_mode_has_segment_map(dcp_iop_mode)) {
            size_t seg_count = 0;
            const AppleModernAdtOverride *seg =
                apple_modern_dcp_iop_segment_overrides(&seg_count);
            for (size_t i = 0; i < seg_count; i++) {
                if (override_count >= APPLE_MODERN_MAX_ADT_OVERRIDES) {
                    error_report("apple-modern: too many ADT overrides");
                    exit(EXIT_FAILURE);
                }
                overrides[override_count++] = seg[i];
            }
            warn_report("apple-modern: dcp-iop '%s' serves %zu DECLARED ADT "
                        "segment properties on /arm-io/dcp/iop-dcp-nub "
                        "(region-base = 0x%" PRIx64 ", region-size = 0x%" PRIx64
                        ") following the /arm-io/smc/iop-smc-nub pattern",
                        s->dcp_iop, seg_count,
                        APPLE_MODERN_DCP_IOP_SEGMENT_BASE,
                        APPLE_MODERN_DCP_IOP_SEGMENT_SIZE);
        }
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
    if (s->sepfw_absent) {
        /*
         * Attested consumers in BootKC a36b9241: AppleSEPKeyStore decides
         * whether SEP firmware is expected from the SEP service's
         * "sep-booted" or, failing that, IODeviceTree:/chosen
         * "sepfw-load-at-boot" (unslid 0xfffffff0095ca548), and
         * AppleCredentialManager logs "isSEPAvailable" from the same /chosen
         * property. No SEP firmware executes on this board, so the template
         * value 1 leaves both waiting for an AppleSEPManager that never
         * appears ("ACMTRM: waitForSEPEndpoint: timed out" every 5 s) and
         * keybag clients block. /chosen is loader-owned, so the loader writes
         * the value itself. Declared guest modification, default off.
         */
        metadata_input.chosen_sepfw_absent = true;
        warn_report("apple-modern: sepfw-absent serves /chosen "
                    "sepfw-load-at-boot = 0 (declared: no SEP firmware runs)");
    }
    if (s->pmgr_ungate) {
        size_t ungate_count = 0;
        const AppleModernAdtOverride *ungate =
            apple_modern_pmgr_ungate_overrides(&ungate_count);

        /*
         * Attested (AppleT8140, AppleH17PPlatformIO::start at
         * 0xfffffff00979775c in BootKC a36b9241...): the driver reads
         * "no-clock-gate" and "no-power-gate" off its /arm-io node and, when
         * either is present, branches over the matching
         * function-clock_gate / function-power_gate lookup, so no gate action
         * is ever registered. Absent both the property and the escape hatch it
         * panics at AppleH17PPlatformIO.cpp:94 / :100. Only presence is
         * tested, so the value is a single declared nonzero byte (the
         * override ABI has no zero-length form).
         */
        for (size_t i = 0; i < ungate_count; i++) {
            overrides[override_count++] = ungate[i];
        }
        warn_report("apple-modern: pmgr-ungate serves /arm-io no-clock-gate "
                    "and no-power-gate (declared guest modification: the "
                    "kernel can no longer clock- or power-gate any /arm-io "
                    "device through /arm-io/pmgr)");
    }
    if (override_count) {
        metadata_input.overrides = overrides;
        metadata_input.override_count = override_count;
    }
    if (s->gpu_iouat_zero) {
        metadata_input.chosen_gpu_iouat_zero = true;
        warn_report("apple-modern: gpu-iouat-zero serves /chosen gpu-iouat = 0 "
                    "(SPTM uat_is_enabled returns false; declared: no GPU UAT)");
    }
    if (s->stub_ioacceles) {
        /*
         * Publish /arm-io/IOAcceleratorES so QC's NameMatching wait exits on
         * the first poll without a DSC text poke (CS-safe). Mutually exclusive
         * with sgx=on: both use the single added_node slot. See
         * modern-adt-ioaccelerator-es.h.
         */
        if (s->sgx) {
            warn_report("apple-modern: stub-ioacceles=on ignores sgx=on "
                        "(added_node is singular; prefer stub for Metal fail-fast)");
        }
        metadata_input.added_node = apple_modern_adt_ioaccelerator_es_node();
        warn_report("apple-modern: stub-ioacceles=on serves /arm-io/"
                    "IOAcceleratorES (name+phandle) for QC "
                    "IOServiceNameMatching fail-fast");
    } else if (s->sgx) {
        /*
         * Serve the GPU node AGXAcceleratorG17P matches. An override can only
         * set a property on a node that already exists, and the served tree
         * DELETES /arm-io/sgx (measured: "gpu,t8140" occurs once in
         * dtree.stock and in none of the 17 other trees in
         * runtime/darwin-reference-27 nor in any prepared tree), so this goes
         * through the synthesized-node path instead. See modern-adt-sgx.h.
         */
        metadata_input.added_node = apple_modern_adt_sgx_node();
        warn_report("apple-modern: sgx=on serves /arm-io/sgx from the pinned "
                    "stock tree (26 properties, compatible \"gpu,t8140\"), so "
                    "AGXAcceleratorG17P can match AppleARMIODevice. MEASURED "
                    "BOOT-STOPPER: SPTM keys its GPU address translator on this "
                    "node and panics in uat_bootstrap_parse_dt before the "
                    "console, because the stock node has no "
                    "gfx-shared-region-base (see modern-adt-sgx.h). Expect zero "
                    "serial output until /chosen gpu-iouat = 0 or the real "
                    "carveout hand-off is served");
    }
    metadata_input.assign_dart_ids = s->adt_dart_ids;
    if (!apple_modern_boot_metadata_build(&metadata_input, &s->metadata, &error) ||
        !uart_address(s->components.dtree, &uart, &uart_span, &s->uart_irq,
                      &error)) {
        error_report_err(error);
        exit(EXIT_FAILURE);
    }
    if (s->metadata.layout.gfx_carveout_size) {
        /*
         * Report the reserved range so the ADT GPU handoff properties
         * (gfx-shared-region-base/-size, gfx-shared-l2-region-base/-size,
         * gpu-region-base/-size, gfx-handoff-base/-size) can be pointed at
         * unmanaged pages. All four must be 16 KiB aligned.
         */
        warn_report("apple-modern: gfx-carveout reserved 0x%" PRIx64 " bytes "
                    "of UNMANAGED DRAM at 0x%" PRIx64 " (memSize reduced; "
                    "point the ADT gfx-shared-region-base / "
                    "gfx-shared-l2-region-base / gpu-region-base / "
                    "gfx-handoff-base at this range)",
                    s->metadata.layout.gfx_carveout_size,
                    s->metadata.layout.gfx_carveout_physical);
    }
    if (s->boot_display && s->dcp_iop &&
        !strcmp(s->dcp_iop, APPLE_MODERN_DCP_IOP_NAME_V6_RESUMED)) {
        AppleModernBlob ds;
        Error *ds_error = NULL;
        if (apple_modern_adt_property((AppleModernBlob){s->metadata.dtree,
                s->metadata.dtree_size}, "/chosen", "display-scale",
                &ds, &ds_error)) {
            if (ds.size == 4 && ldl_le_p(ds.data) == 0) {
                stl_le_p((void *)ds.data, 2);
            }
        } else {
            error_free(ds_error);
        }
    }
    if (s->adt_dart_ids) {
        warn_report("apple-modern: served dart-id 0..%u on %u dart,t8110 "
                    "nodes in ADT order (declared: SPTM requires the "
                    "property, iBoot's own numbering is unmeasured)",
                    s->metadata.dart_id_count - 1, s->metadata.dart_id_count);
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
    if (s->md0_width_compat) {
        /*
         * Declared, opt-in guest-kernel compatibility edit on the private
         * in-memory boot kernel cache only. See modern-kc-patch.h for the
         * published-source root cause (xnu bsd/dev/memdev.c computes the md
         * ram-disk byte size as a 32-bit `mdSize << 12`), the exact file:line
         * list and what it removes.
         */
        AppleModernMd0WidthPatch md0 = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_md0_width_compat(bootkc,
                                              s->blobs[ASSET_BOOTKC].size,
                                              &md0, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in md0-width-compat patch to "
                    "the in-memory kernel cache: mdevstrategy shift at "
                    "0x%" PRIx64 " and DKIOCGETBLOCKCOUNT chain at "
                    "0x%" PRIx64 " widened from 32 to 64 bit "
                    "(4 instructions, 0x%08x->0x%08x and "
                    "0x%08x/0x%08x/0x%08x->0x%08x/0x%08x/0x%08x). This "
                    "REMOVES the 32-bit wrap that makes an md ram disk of "
                    "4 GiB or more report (size mod 2^32) bytes; it removes "
                    "no authentication, signing or integrity check. "
                    "Compatibility, not Apple fidelity",
                    md0.strategy_anchor, md0.blockcount_anchor,
                    md0.strategy_before, md0.strategy_after,
                    md0.blockcount_before[0], md0.blockcount_before[1],
                    md0.blockcount_before[2], md0.blockcount_after[0],
                    md0.blockcount_after[1], md0.blockcount_after[2]);
    }
    if (s->root_rw_compat) {
        /*
         * Declared, opt-in guest-kernel compatibility edit on the private
         * in-memory boot kernel cache only. See modern-kc-patch.h for the
         * published-source root cause (xnu bsd/vfs/vfs_subr.c:1145-1150
         * initializes root mount flags with MNT_RDONLY | MNT_ROOTFS).
         */
        AppleModernRootRwPatch rrw = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_root_rw_compat(bootkc,
                                            s->blobs[ASSET_BOOTKC].size,
                                            &rrw, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in root-rw-compat patch to "
                    "the in-memory kernel cache: vfs_rootmountalloc_internal "
                    "at 0x%" PRIx64 " (MOVZ at +12: 0x%08x->0x%08x), "
                    "__mac_mount root-update check at 0x%" PRIx64 " -> 0x%"
                    PRIx64 " (TBNZ at +4: 0x%08x->0x%08x). Compatibility, "
                    "not Apple fidelity",
                    rrw.rootmountalloc_anchor,
                    rrw.rootmountalloc_before, rrw.rootmountalloc_after,
                    rrw.check_anchor, rrw.update_anchor,
                    rrw.insn_before, rrw.insn_after);
    }
    if (s->txm_sc_compat) {
        AppleModernTxmScPatch tsc = { 0 };
        uint8_t *txm = (uint8_t *)s->blobs[ASSET_TXM].data;

        if (!apple_modern_txm_sc_compat(txm, s->blobs[ASSET_TXM].size,
                                        &tsc, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in txm-sc-compat patch to the "
                    "in-memory TXM image at +0x%" PRIx64 " (prologue 0x%08x, "
                    "+4/+8: 0x%08x/0x%08x -> 0x%08x/0x%08x). Compatibility, "
                    "not Apple fidelity",
                    tsc.anchor, tsc.prologue,
                    tsc.insn_before[0], tsc.insn_before[1],
                    tsc.insn_after[0], tsc.insn_after[1]);
    }
    if (s->iouc_sandbox_compat) {
        AppleModernIoucPatch iouc = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_iouc_sandbox_compat(bootkc,
                                                 s->blobs[ASSET_BOOTKC].size,
                                                 &iouc, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in iouc-sandbox-compat patch to the "
                    "in-memory kernel cache: sandbox deny at 0x%" PRIx64 " (0x%08x->0x%08x), "
                    "MACF gate at 0x%" PRIx64 " (0x%08x->0x%08x). Compatibility, not "
                    "Apple fidelity",
                    iouc.sandbox_deny_anchor, iouc.sandbox_deny_before, iouc.sandbox_deny_after,
                    iouc.macf_gate_anchor, iouc.macf_gate_before, iouc.macf_gate_after);
    }
    if (s->amfi_csstatus_platform_compat) {
        AppleModernAmfiCsStatusPatch acs = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_amfi_csstatus_platform_compat(
                bootkc, s->blobs[ASSET_BOOTKC].size, &acs, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in amfi-csstatus-platform-compat "
                    "patch to the in-memory kernel cache: csops CS_OPS_STATUS "
                    "platform gate at 0x%" PRIx64 " (0x%08x->0x%08x) so "
                    "csops/csops_audittoken(CS_OPS_STATUS) always report "
                    "CS_PLATFORM_BINARY (satisfies launchd RequireTrusted "
                    "subscriber trust). Compatibility, not Apple fidelity",
                    acs.anchor, acs.insn_before, acs.insn_after);
    }
    if (s->platform_binary_force_compat) {
        AppleModernPlatBinPatch pbf = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_platform_binary_force_compat(
                bootkc, s->blobs[ASSET_BOOTKC].size, &pbf, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in platform-binary-force-compat "
                    "patch to the in-memory kernel cache: "
                    "csproc_get_platform_binary at 0x%" PRIx64 " forced to "
                    "return 1 (+4/+8: 0x%08x/0x%08x -> 0x%08x/0x%08x) so every "
                    "process is a platform binary kernel-wide. Compatibility, "
                    "not Apple fidelity",
                    pbf.anchor, pbf.insn_before[0], pbf.insn_before[1],
                    pbf.insn_after[0], pbf.insn_after[1]);
    }
    if (s->rootvp_auth_skip_compat) {
        AppleModernRootvpSkipPatch rvp = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_rootvp_auth_skip_compat(
                bootkc, s->blobs[ASSET_BOOTKC].size, &rvp, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in rootvp-auth-skip-compat patch "
                    "to the in-memory kernel cache: bsd_init ramdisk-skip at "
                    "0x%" PRIx64 " (0x%08x->0x%08x) so rootdev=md0 (normal boot) "
                    "skips the root-vnode auth check like rd=md0 does. "
                    "Compatibility, not Apple fidelity",
                    rvp.anchor, rvp.insn_before, rvp.insn_after);
    }
    if (s->vekd_unenc_data_compat) {
        AppleModernVekdPatch vekd = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_vekd_unenc_data_compat(
                bootkc, s->blobs[ASSET_BOOTKC].size, &vekd, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in vekd-unenc-data-compat patch "
                    "to the in-memory kernel cache: apfs unencrypted-data guard "
                    "at 0x%" PRIx64 " (0x%08x->0x%08x) so a PLAIN Data volume "
                    "mounts without the role64+unencrypted panic. "
                    "Compatibility, not Apple fidelity",
                    vekd.anchor, vekd.insn_before, vekd.insn_after);
    }
    if (s->keystore_persona_stub_compat) {
        AppleModernKeystoreStubPatch ks = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_keystore_persona_stub_compat(
                bootkc, s->blobs[ASSET_BOOTKC].size, &ks, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: applied opt-in keystore-persona-stub-compat "
                    "patch to the in-memory kernel cache: AppleSEPKeyStore "
                    "persona-UUID mapping forced to success at 0x%" PRIx64
                    " (0x%08x/0x%08x -> 0x%08x/0x%08x) so persona-6 bring-up "
                    "does not fail 0xe007c022 on a PLAIN Data volume with no real "
                    "SEP keybag. Compatibility, not Apple fidelity",
                    ks.anchor, ks.insn_before0, ks.insn_before1,
                    ks.insn_after0, ks.insn_after1);
    }
    if (s->sepfw_absent) {
        /*
         * sks-failfast / sepfw-absent also NOPs the second AppleSEPKeyStore
         * wait (user-client open BLRAA at 0xfffffff0095cf27c). See
         * modern-kc-patch.h sks-open-wait-skip.
         */
        AppleModernSksOpenWaitPatch sow = { 0 };
        uint8_t *bootkc = (uint8_t *)s->blobs[ASSET_BOOTKC].data;

        if (!apple_modern_kc_sks_open_wait_skip(
                bootkc, s->blobs[ASSET_BOOTKC].size, &sow, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        warn_report("apple-modern: sks-failfast applied sks-open-wait-skip "
                    "to the in-memory kernel cache: NOP'd AppleSEPKeyStore "
                    "user-client open BLRAA at 0x%" PRIx64
                    " (0x%08x->0x%08x) so waitForMatchingService(AppleSEPManager) "
                    "is not taken; open still returns success. Compatibility, "
                    "not Apple fidelity",
                    sow.anchor, sow.insn_before, sow.insn_after);
    }
    if (s->image_patches) {
        /*
         * Declared, opt-in anchored image patches on the board's private
         * in-memory image copies only. See modern-image-patch.h. Default board
         * sets no set and is byte-identical to an unpatched board.
         */
        if (!apply_image_patches(s, &error)) {
            error_report_err(error);
            exit(EXIT_FAILURE);
        }
        for (size_t i = 0; i < s->image_patch_result.count; i++) {
            const AppleModernImagePatchApplied *a =
                &s->image_patch_result.entries[i];
            warn_report("apple-modern: applied declared image-patch '%s' "
                        "(set '%s'): %s [removes: %s] (declared modification, "
                        "not Apple fidelity)", a->name, s->image_patches,
                        a->changes, a->removes);
        }
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
    /*
     * mc->default_ram_id makes the machine core own the DRAM region: by
     * default a memory-backend-ram of machine->ram_size named exactly as the
     * board's old region ("apple-modern.ram", same migration ramblock id), or
     * the user's "-object memory-backend-file,... -machine memory-backend=..."
     * when one is given. Migratable RAM's owner must be a DeviceState or
     * NULL, not MachineState, which the backend satisfies.
     */
    s->ram = machine->ram;
    if (!s->ram || memory_region_size(s->ram) != machine->ram_size) {
        error_report("apple-modern: machine RAM region is missing or sized "
                     "differently from -m");
        exit(EXIT_FAILURE);
    }
    memory_region_add_subregion(get_system_memory(), s->components.dram_base,
                                s->ram);
    if (s->large_ramdisk) {
        uint64_t rounded = s->metadata.layout.ramdisk_size;
        rounded = (rounded + APPLE_MODERN_PAGE_SIZE - 1) &
                  ~(APPLE_MODERN_PAGE_SIZE - 1);
        if (rounded > s->large_ramdisk_file.map_size) {
            error_report("apple-modern: mapped ramdisk is shorter than its "
                         "reservation");
            exit(EXIT_FAILURE);
        }
        /*
         * Published over the DRAM window at a higher priority, so the guest
         * reads the file's bytes at the layout's RAMDisk address with no copy
         * and no second allocation. Not registered for migration.
         */
        memory_region_init_ram_ptr(&s->large_ramdisk_mr, NULL,
                                   "apple-modern.large-ramdisk", rounded,
                                   s->large_ramdisk_file.host);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            s->metadata.layout.ramdisk_physical,
                                            &s->large_ramdisk_mr, 1);
    }
    if (s->boot_display && !apple_modern_boot_display_create(
            s->ram, s->metadata.layout.framebuffer_physical -
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
        (s->gfx_asc && !map_gfx_mailbox(s, &error)) ||
        ((s->sgx || s->gpu_trace) && !map_sgx_trace(s, &error)) ||
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
        (s->dcp_asc && !map_dcp_asc(s, uart, uart_span, &error)) ||
        (s->modern_smc && !map_modern_smc(s, uart, uart_span, &error)) ||
        ((s->dcp_iop || s->dcp_attach_cbs || s->dcp_attach_trigger) &&
         !map_dcp_iop(s, uart, uart_span, &error)) ||
        (s->disp0_probe && !map_disp_trace(s, uart, uart_span, &error)) ||
        (s->modern_pmgr_storage &&
         !map_pmgr_storage(s, uart, uart_span, &error)) ||
        (s->pmgr_aon_fuse_image &&
         !map_pmgr_fuse(s, uart, uart_span, &error)) ||
        (s->modern_pmgr && !map_pmgr(s, uart, uart_span, &error)) ||
        (s->modern_ans && !modern_create_ans(s, &error)) ||
        (s->disp0_pipe && !map_disp0(s, uart, uart_span, &error))) {
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
    if (s->el0_trap_trace) {
        object_property_set_bool(OBJECT(s->cpu),
                                 "apple-modern-el0-trap-trace", true,
                                 &error_fatal);
        warn_report("apple-modern: EL0 BRK traps are reported on the QEMU side "
                    "(opt-in el0-trap-trace; observability only, guest "
                    "behaviour is unchanged)");
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

static char *get_disp0_probe(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->disp0_probe);
}

static void set_disp0_probe(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (!check_mutable(s, errp)) {
        return;
    }
    if (value && *value && strcmp(value, "off")) {
        g_free(s->disp0_probe);
        s->disp0_probe = g_strdup(value);
    } else {
        g_free(s->disp0_probe);
        s->disp0_probe = NULL;
    }
}

static char *get_adt_compat_restore(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->adt_compat_restore);
}

static void set_adt_compat_restore(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (!check_mutable(s, errp)) {
        return;
    }
    g_free(s->adt_compat_restore);
    s->adt_compat_restore = (value && *value && strcmp(value, "off")) ?
                            g_strdup(value) : NULL;
}

static char *get_ramdisk_patches(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->ramdisk_patches);
}

static void set_ramdisk_patches(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->ramdisk_patches);
        s->ramdisk_patches = value && value[0] && strcmp(value, "off") ?
                             g_strdup(value) : NULL;
    }
}

static char *get_dcp_attach_cbs(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->dcp_attach_cbs);
}

static void set_dcp_attach_cbs(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->dcp_attach_cbs);
        s->dcp_attach_cbs = value && value[0] && strcmp(value, "off") ?
                            g_strdup(value) : NULL;
    }
}

static char *get_dcp_attach_trigger(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->dcp_attach_trigger);
}

static void set_dcp_attach_trigger(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->dcp_attach_trigger);
        s->dcp_attach_trigger = value && value[0] ? g_strdup(value) : NULL;
    }
}

static char *get_dcp_iop(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->dcp_iop);
}

static void set_dcp_iop(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->dcp_iop);
        s->dcp_iop = value && value[0] && strcmp(value, "off") ?
                     g_strdup(value) : NULL;
    }
}

static char *get_dcp_asc(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->dcp_asc);
}

static void set_dcp_asc(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->dcp_asc);
        s->dcp_asc = value && value[0] ? g_strdup(value) : NULL;
    }
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

static char *get_image_patches(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->image_patches);
}

static void set_image_patches(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->image_patches);
        /* Empty string means "no set", like the default. */
        s->image_patches = (value && value[0]) ? g_strdup(value) : NULL;
    }
}

static char *get_modern_ans_image(Object *obj, Error **errp)
{
    return g_strdup(APPLE_MODERN_MACHINE(obj)->modern_ans_image);
}

static void set_modern_ans_image(Object *obj, const char *value, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    if (check_mutable(s, errp)) {
        g_free(s->modern_ans_image);
        s->modern_ans_image = (value && value[0]) ? g_strdup(value) : NULL;
    }
}

/* Read-only: comma-separated names of the patches actually applied, for gates. */
static char *get_applied_image_patches(Object *obj, Error **errp)
{
    AppleModernMachine *s = APPLE_MODERN_MACHINE(obj);
    GString *list = g_string_new(NULL);

    for (size_t i = 0; i < s->image_patch_result.count; i++) {
        g_string_append_printf(list, "%s%s", i ? "," : "",
                               s->image_patch_result.entries[i].name);
    }
    return g_string_free(list, FALSE);
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
ASSET_PROPERTY(cryptex_trustcache, ASSET_CRYPTEX_TC)
#undef ASSET_PROPERTY

#define BOOL_PROPERTY(name, field) \
    static bool get_##name(Object *obj, Error **errp) \
    { return APPLE_MODERN_MACHINE(obj)->field; } \
    static void set_##name(Object *obj, bool value, Error **errp) \
    { AppleModernMachine *s = APPLE_MODERN_MACHINE(obj); \
      if (check_mutable(s, errp)) { s->field = value; } }
BOOL_PROPERTY(img4_ignition_compat, img4_ignition_compat)
BOOL_PROPERTY(trustcache_v2, trustcache_v2)
BOOL_PROPERTY(md0_width_compat, md0_width_compat)
BOOL_PROPERTY(root_rw_compat, root_rw_compat)
BOOL_PROPERTY(txm_sc_compat, txm_sc_compat)
BOOL_PROPERTY(iouc_sandbox_compat, iouc_sandbox_compat)
BOOL_PROPERTY(amfi_csstatus_platform_compat, amfi_csstatus_platform_compat)
BOOL_PROPERTY(platform_binary_force_compat, platform_binary_force_compat)
BOOL_PROPERTY(rootvp_auth_skip_compat, rootvp_auth_skip_compat)
BOOL_PROPERTY(vekd_unenc_data_compat, vekd_unenc_data_compat)
BOOL_PROPERTY(keystore_persona_stub_compat, keystore_persona_stub_compat)
BOOL_PROPERTY(gfx_asc, gfx_asc)
BOOL_PROPERTY(gfx_carveout, gfx_carveout)
BOOL_PROPERTY(gpu_trace, gpu_trace)
BOOL_PROPERTY(gpu_trace_answer, gpu_trace_answer)
BOOL_PROPERTY(sgx, sgx)
BOOL_PROPERTY(stub_ioacceles, stub_ioacceles)
BOOL_PROPERTY(gpu_iouat_zero, gpu_iouat_zero)
BOOL_PROPERTY(modern_ans, modern_ans)
BOOL_PROPERTY(pauth_compat, pauth_compat)
BOOL_PROPERTY(el0_trap_trace, el0_trap_trace)
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
BOOL_PROPERTY(sepfw_absent, sepfw_absent)
BOOL_PROPERTY(adt_dart_ids, adt_dart_ids)
BOOL_PROPERTY(large_ramdisk, large_ramdisk)
BOOL_PROPERTY(pmgr_ungate, pmgr_ungate)
BOOL_PROPERTY(modern_pmp_ptd, modern_pmp_ptd)
BOOL_PROPERTY(modern_cpu_dvfm, modern_cpu_dvfm)
BOOL_PROPERTY(modern_pmgr_storage, modern_pmgr_storage)
BOOL_PROPERTY(modern_mcc_dsid, modern_mcc_dsid)
BOOL_PROPERTY(modern_mcc_slc, modern_mcc_slc)
BOOL_PROPERTY(aic_trace, aic_trace)
BOOL_PROPERTY(modern_aic, modern_aic)
BOOL_PROPERTY(modern_smc, modern_smc)
BOOL_PROPERTY(modern_smc_buttons, modern_smc_buttons)
BOOL_PROPERTY(aic_record_irq_config, aic_record_irq_config)
BOOL_PROPERTY(boot_display, boot_display)
BOOL_PROPERTY(disp0_pipe, disp0_pipe)
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
    apple_modern_large_ramdisk_unmap(&s->large_ramdisk_file);
    g_free(s->boot_command_line);
    g_free(s->pmgr_aon_fuse_image);
    g_free(s->pmgr_voltage_states);
    g_free(s->pmgr_boot_on);
    g_free(s->image_patches);
    g_free(s->disp0_probe);
    g_free(s->adt_compat_restore);
    g_free(s->dcp_asc);
    g_free(s->dcp_iop);
    g_free(s->dcp_attach_cbs);
    g_free(s->dcp_attach_trigger);
    g_free(s->ramdisk_patches);
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
    /*
     * Same name as the region the board used to create itself, so the
     * migration ramblock id is unchanged and "-object
     * memory-backend-file,id=X,... -machine memory-backend=X" can back guest
     * DRAM with a (sparse) host file instead of anonymous memory.
     */
    mc->default_ram_id = "apple-modern.ram";
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("max");
    object_class_property_add_str(oc, "bootkc", get_bootkc, set_bootkc);
    object_class_property_add_str(oc, "sptm", get_sptm, set_sptm);
    object_class_property_add_str(oc, "txm", get_txm, set_txm);
    object_class_property_add_str(oc, "dtree", get_dtree, set_dtree);
    object_class_property_add_str(oc, "tc", get_tc, set_tc);
    /*
     * Opt-in, absent by default: a second Apple trust-cache module. The only
     * reason it exists is the OS cryptex -- on a device libignition grafts the
     * cryptex and loads that cryptex's own trust cache before dyld looks for
     * the shared cache, and a board that presents the cryptex's content
     * without grafting it has no one to do that. Needs trustcache-v2=on for
     * Apple's own version-2 modules.
     */
    object_class_property_add_str(oc, "cryptex-trustcache",
                                  get_cryptex_trustcache,
                                  set_cryptex_trustcache);
    object_class_property_add_str(oc, "ramdisk", get_ramdisk, set_ramdisk);
    object_class_property_add_bool(oc, "modern-pmp-ptd", get_modern_pmp_ptd,
                                   set_modern_pmp_ptd);
    object_class_property_add_bool(oc, "modern-cpu-dvfm", get_modern_cpu_dvfm,
                                   set_modern_cpu_dvfm);
    object_class_property_add_bool(oc, "modern-pmgr-storage",
                                   get_modern_pmgr_storage, set_modern_pmgr_storage);
    object_class_property_add_bool(oc, "adt-timebase-match", get_adt_timebase_match,
                                   set_adt_timebase_match);
    object_class_property_add_bool(oc, "sepfw-absent", get_sepfw_absent,
                                   set_sepfw_absent);
    object_class_property_set_description(oc, "sepfw-absent",
        "serve /chosen sepfw-load-at-boot = 0 so AppleSEPKeyStore and "
        "AppleCredentialManager do not wait for SEP firmware that never runs "
        "(declared guest modification, default off)");
    /*
     * sks-failfast: alias of sepfw-absent, named for the msg2862 / AppleSEPKeyStore
     * IOServiceOpen unblock. Grok RE 2026-10-17 + angr proof
     * (Grok/impl-20261017/re/symex/sks_release_symex.json) show that
     * AppleSEPKeyStore::getEndpoint (0xfffffff0095ca694) blocks forever in
     * sep_endpoint() when isSEPExpected (0xfffffff0095ca544) returns 1, and
     * takes the no-wait "SEP is not booted" path when it returns 0. Serving
     * /chosen sepfw-load-at-boot=0 forces that return to 0, releasing the
     * synchronous io_service_open_extended (msgh_id 2862) wait that
     * backboardd (PearlEventFilter -> MKBGetDeviceLockState -> aks_get_lock_state
     * -> IOServiceOpen) and biomed both hit. Same storage as sepfw-absent.
     */
    object_class_property_add_bool(oc, "sks-failfast", get_sepfw_absent,
                                   set_sepfw_absent);
    object_class_property_set_description(oc, "sks-failfast",
        "alias of sepfw-absent: make AppleSEPKeyStore open fail-fast (no SEP "
        "endpoint wait) so io_service_open_extended (msg 2862) returns; "
        "default off");
    object_class_property_add_bool(oc, "pmgr-ungate", get_pmgr_ungate,
                                   set_pmgr_ungate);
    object_class_property_add_bool(oc, "adt-dart-ids", get_adt_dart_ids,
                                   set_adt_dart_ids);
    object_class_property_add_bool(oc, "large-ramdisk", get_large_ramdisk,
                                   set_large_ramdisk);
    object_class_property_add_str(oc, "pmgr-boot-on", get_pmgr_boot_on,
                                  set_pmgr_boot_on);
    object_class_property_add_str(oc, "disp0-probe", get_disp0_probe,
                                  set_disp0_probe);
    object_class_property_add_str(oc, "adt-compat-restore",
                                  get_adt_compat_restore,
                                  set_adt_compat_restore);
    object_class_property_add_str(oc, "dcp-asc", get_dcp_asc, set_dcp_asc);
    object_class_property_add_str(oc, "dcp-iop", get_dcp_iop, set_dcp_iop);
    object_class_property_add_str(oc, "ramdisk-patches", get_ramdisk_patches,
                                  set_ramdisk_patches);
    object_class_property_set_description(oc, "ramdisk-patches",
        "path of a list of declared same-size edits ('<offset> <old-hex> "
        "<new-hex>' per line, all verified first) applied to the private "
        "large-ramdisk mapping; the image file is never written");
    object_class_property_add_str(oc, "dcp-attach-cbs", get_dcp_attach_cbs,
                                  set_dcp_attach_cbs);
    object_class_property_set_description(oc, "dcp-attach-cbs",
        "v6-resumed display-attach callbacks to send, '+'-separated subset of "
        "D575 (hotPlug_notify_gated) + D600 (setSystemConsoleMode_gated); "
        "default none");
    object_class_property_add_str(oc, "dcp-attach-trigger",
                                  get_dcp_attach_trigger,
                                  set_dcp_attach_trigger);
    object_class_property_set_description(oc, "dcp-attach-trigger",
        "when to send dcp-attach-cbs: normal-mode (nested in NormalModeEnable, "
        "default) or a453 (nested in the first get_display_size after it)");
    object_class_property_add_str(oc, "pmgr-voltage-states",
                                  get_pmgr_voltage_states,
                                  set_pmgr_voltage_states);
    object_class_property_add_str(oc, "pmgr-aon-fuse-image",
                                   get_pmgr_aon_fuse_image,
                                   set_pmgr_aon_fuse_image);
    object_class_property_add_str(oc, "boot-command-line", get_boot_command_line,
                                  set_boot_command_line);
    object_class_property_add_bool(oc, "trustcache-v2", get_trustcache_v2,
                                   set_trustcache_v2);
    object_class_property_add_bool(oc, "pauth-compat", get_pauth_compat,
                                   set_pauth_compat);
    object_class_property_add_bool(oc, "el0-trap-trace", get_el0_trap_trace,
                                   set_el0_trap_trace);
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
    object_class_property_add_bool(oc, "modern-smc-buttons",
                                   get_modern_smc_buttons,
                                   set_modern_smc_buttons);
    object_class_property_add_bool(oc, "modern-smc", get_modern_smc,
                                   set_modern_smc);
    object_class_property_add_bool(oc, "modern-aic", get_modern_aic,
                                   set_modern_aic);
    object_class_property_add_bool(oc, "aic-record-irq-config",
                                   get_aic_record_irq_config,
                                   set_aic_record_irq_config);
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
    object_class_property_add_bool(oc, "md0-width-compat",
                                   get_md0_width_compat,
                                   set_md0_width_compat);
    object_class_property_add_bool(oc, "root-rw-compat",
                                   get_root_rw_compat,
                                   set_root_rw_compat);
    object_class_property_add_bool(oc, "txm-sc-compat",
                                   get_txm_sc_compat,
                                   set_txm_sc_compat);
    object_class_property_add_bool(oc, "iouc-sandbox-compat",
                                   get_iouc_sandbox_compat,
                                   set_iouc_sandbox_compat);
    object_class_property_add_bool(oc, "amfi-csstatus-platform-compat",
                                   get_amfi_csstatus_platform_compat,
                                   set_amfi_csstatus_platform_compat);
    object_class_property_add_bool(oc, "platform-binary-force-compat",
                                   get_platform_binary_force_compat,
                                   set_platform_binary_force_compat);
    object_class_property_add_bool(oc, "rootvp-auth-skip-compat",
                                   get_rootvp_auth_skip_compat,
                                   set_rootvp_auth_skip_compat);
    object_class_property_add_bool(oc, "vekd-unenc-data-compat",
                                   get_vekd_unenc_data_compat,
                                   set_vekd_unenc_data_compat);
    object_class_property_add_bool(oc, "keystore-persona-stub-compat",
                                   get_keystore_persona_stub_compat,
                                   set_keystore_persona_stub_compat);
    object_class_property_add_bool(oc, "gfx-asc", get_gfx_asc, set_gfx_asc);
    object_class_property_add_bool(oc, "gfx-carveout", get_gfx_carveout,
                                   set_gfx_carveout);
    object_class_property_add_bool(oc, "gpu-trace", get_gpu_trace,
                                   set_gpu_trace);
    object_class_property_add_bool(oc, "gpu-trace-answer",
                                   get_gpu_trace_answer,
                                   set_gpu_trace_answer);
    object_class_property_add_bool(oc, "sgx", get_sgx, set_sgx);
    object_class_property_add_bool(oc, "stub-ioacceles", get_stub_ioacceles,
                                   set_stub_ioacceles);
    object_class_property_add_bool(oc, "gpu-iouat-zero", get_gpu_iouat_zero,
                                   set_gpu_iouat_zero);
    object_class_property_add_bool(oc, "modern-ans", get_modern_ans,
                                   set_modern_ans);
    object_class_property_add_str(oc, "modern-ans-image", get_modern_ans_image,
                                  set_modern_ans_image);
    object_class_property_add_str(oc, "image-patches", get_image_patches,
                                  set_image_patches);
    object_class_property_add_str(oc, "applied-image-patches",
                                  get_applied_image_patches, NULL);
    object_class_property_add_bool(oc, "prepare-only", get_prepare_only, set_prepare_only);
    object_class_property_add_bool(oc, "boot-display", get_boot_display,
                                   set_boot_display);
    object_class_property_add_bool(oc, "disp0-pipe", get_disp0_pipe,
                                   set_disp0_pipe);
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
