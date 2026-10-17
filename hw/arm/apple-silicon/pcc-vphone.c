/*
 * vphone-pcc: direct-loader prototype for the cloudOS/PCC 26.4 (23E5207q)
 * vphone600ap virtual iPhone on a vmapple-class board under TCG.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * grok/pcc-vmapple. A new, separate machine: it shares only the strict
 * apple-modern layout/metadata builders (opted in with platform_vmapple1)
 * and the apple-modern CPU profile. The t8140 "apple-modern" machine is not
 * touched. There is no AVPBooter/iBoot here: this board does iBoot's hand-off
 * itself (place SPTM/TXM/kernelcache/DT/trust caches, fill /chosen and
 * /chosen/memory-map, write boot_args, enter SPTM with x0 = boot_args).
 *
 * Board map = DeviceTree.vphone600ap /arm-io (ranges child 0 -> 0x10000000),
 * which is QEMU's upstream vmapple map plus avp-ctrr, avp-rtc and sep:
 *   GICv3 dist 0x10000000, redist 0x10010000     PL011 0x20010000 (SPI 1)
 *   PL031 0x20050000 (SPI 2)  PL061 0x20060000 (SPI 5)  pvpanic 0x20070000
 *   gfx (APV_GFX) 0x30200000 SPI 17   iosurface-mapper 0x30210000 SPI 16
 *   aes 0x30220000/0x30230000 SPI 18  avp-rtc 0x30240000 SPI 19
 *   sep (iop-sep,vpiop) 0x30250000 +1MiB SPI 20/21   avp-ctrr 0x30260000
 *   PCIe ECAM 0x40000000, MMIO 0x50000000   DRAM 0x70000000
 * Evidence: vresearch1 SPTM runs at EL1/GL1 (entry 0xfffffff0270a7000 writes
 * OSLAR_EL1 and VBAR_EL1; no HCR_EL2/TPIDR_EL2 access at all, against 29
 * HCR_EL2 and 177 TPIDR_EL2 accesses in the t8140 SPTM), so the CPU enters
 * SPTM at EL1h, as Virtualization.framework does for its guests.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "qemu/module.h"
#include "hw/boards.h"
#include "hw/core/cpu.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "hw/char/pl011.h"
#include "hw/intc/arm_gicv3_common.h"
#include "hw/misc/unimp.h"
#include "hw/pci-host/gpex.h"
#include "hw/arm/apple-silicon/modern-boot-metadata.h"
#include "qobject/qlist.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "system/system.h"
#include "system/runstate.h"
#include "cpu.h"
#include "internals.h"
#include "hw/intc/arm_gic.h"

#define TYPE_VPHONE_PCC_MACHINE MACHINE_TYPE_NAME("vphone-pcc")
OBJECT_DECLARE_SIMPLE_TYPE(VPhonePccMachine, VPHONE_PCC_MACHINE)

#define PCC_DRAM_BASE   UINT64_C(0x70000000)
#define PCC_NUM_IRQS    256

enum { A_KC, A_SPTM, A_TXM, A_DT, A_TC, A_TC2, A_RD, A_COUNT };
static const char *const asset_names[A_COUNT] = {
    "bootkc", "sptm", "txm", "dtree", "tc", "tc2", "ramdisk",
};

typedef struct VPhonePccMachine {
    MachineState parent;
    char *paths[A_COUNT];
    AppleModernBlob blobs[A_COUNT];
    AppleModernBootInput components;
    AppleModernBootMetadata metadata;
    ARMCPU *cpu;
    DeviceState *gic;
    MemoryRegion *ram;
    MemoryRegion ecam_alias;
    char *command_line;
    bool prepare_only;
    bool sepfw_absent;
    bool initialized;
} VPhonePccMachine;

static bool read_asset(const char *path, AppleModernBlob *out, Error **errp)
{
    gsize size = 0;
    gchar *data = NULL;
    GError *gerr = NULL;

    if (!g_file_get_contents(path, &data, &size, &gerr)) {
        error_setg(errp, "vphone-pcc: cannot read %s: %s", path, gerr->message);
        g_error_free(gerr);
        return false;
    }
    *out = (AppleModernBlob){ (const uint8_t *)data, size };
    return true;
}

static void write_memory(uint64_t address, const void *bytes, size_t size)
{
    if (address_space_write(&address_space_memory, address,
                            MEMTXATTRS_UNSPECIFIED, bytes, size) != MEMTX_OK) {
        error_report("vphone-pcc: write failed at 0x%" PRIx64, address);
        exit(EXIT_FAILURE);
    }
}

static void load_prepared_memory(VPhonePccMachine *s)
{
    AppleModernBootLayout *layout = &s->metadata.layout;
    AppleModernBlob sources[] = {
        s->components.bootkc, s->components.sptm, s->components.txm,
        s->components.trustcache, s->components.ramdisk,
    };

    for (size_t i = 0; i < layout->region_count; i++) {
        AppleModernBootRegion *r = &layout->regions[i];
        if (address_space_set(&address_space_memory, r->physical_address, 0,
                              r->size, MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            error_report("vphone-pcc: region zero failed");
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
            continue;
        }
        write_memory(copy->physical_address, source.data + copy->source_offset,
                     copy->file_size);
    }
    write_memory(layout->dtree_physical, s->metadata.dtree,
                 s->metadata.dtree_size);
    write_memory(layout->bootargs_physical, s->metadata.bootargs,
                 sizeof(s->metadata.bootargs));
}

/*
 * Drop to EL1h with a VHE-style identity for the guest: HCR_EL2.RW|E2H,
 * so SCTLR_EL1, TTBR0/1_EL1, TCR_EL1 and VBAR_EL1 that SPTM programs apply to the
 * currently-running (EL1) context. Evidence: the vresearch1 SPTM never
 * touches HCR_EL2 (0 times versus 29 in the t8140 SPTM) and its entry
 * prologue at 0xfffffff0270a7000 programs OSLAR_EL1 and VBAR_EL1.
 *
 * HCR_APK|HCR_API: without APK, access_pauth traps APCTL_EL1 / KERNELKEY*
 * MRS/MSR from EL1 to EL2 (EC=0x18). v11: undef at phys 0x770a75b0
 * (mrs s3_4_c15_c0_4 = APCTL_EL1) -> EL2 PC 0x400 -> prefetch 0x200.
 */
static void enter_el1h(CPUARMState *env)
{
    uint32_t spsr;

    /* E2H only: TGE would collapse EL1 into EL2 and trap OSLAR_EL1. */
    env->cp15.hcr_el2 = HCR_RW | HCR_E2H | HCR_APK | HCR_API;
    /*
     * With E2H, CPTR_EL2.FPEN/ZEN/SMEN use the CPACR layout. Reset FPEN=0
     * traps EL1 SIMD (ldnp q*) to EL2 (v14: ELR 0xfffffe00070a7ec4,
     * ESR EC=0x07). Permit FP/SVE/SME at EL0/EL1/EL2.
     */
    env->cp15.cptr_el[2] |= (3ULL << 20) | (3ULL << 16) | (3ULL << 24);
    spsr = aarch64_pstate_mode(1, true); /* EL1h = 5 */
    spsr |= PSTATE_D | PSTATE_A | PSTATE_I | PSTATE_F;
    aarch64_save_sp(env, 2);
    pstate_write(env, spsr);
    env->aarch64 = true;
    aarch64_restore_sp(env, 1);
    arm_rebuild_hflags(env);
}

static void pcc_reset(void *opaque)
{
    VPhonePccMachine *s = opaque;
    CPUState *cs = CPU(s->cpu);
    CPUARMState *env = &s->cpu->env;

    cpu_reset(cs);
    load_prepared_memory(s);
    enter_el1h(env);
    env->pc = s->metadata.layout.sptm_entry_physical;
    env->xregs[0] = s->metadata.layout.bootargs_physical;
    env->cp15.cpacr_el1 |= 3U << 20;
    cs->halted = s->prepare_only;
    arm_rebuild_hflags(env);
    if (s->prepare_only) {
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
    }
}

static void create_gic(VPhonePccMachine *s)
{
    MachineState *ms = MACHINE(s);
    SysBusDevice *gicbusdev;
    QList *redist_region_count;
    unsigned smp = ms->smp.cpus;
    int i;

    s->gic = qdev_new(gicv3_class_name());
    qdev_prop_set_uint32(s->gic, "revision", 3);
    qdev_prop_set_uint32(s->gic, "num-cpu", smp);
    qdev_prop_set_uint32(s->gic, "num-irq", PCC_NUM_IRQS + 32);
    redist_region_count = qlist_new();
    qlist_append_int(redist_region_count, smp);
    qdev_prop_set_array(s->gic, "redist-region-count", redist_region_count);
    gicbusdev = SYS_BUS_DEVICE(s->gic);
    sysbus_realize_and_unref(gicbusdev, &error_fatal);
    sysbus_mmio_map(gicbusdev, 0, 0x10000000);
    sysbus_mmio_map(gicbusdev, 1, 0x10010000);
    for (i = 0; i < (int)smp; i++) {
        DeviceState *cpudev = DEVICE(qemu_get_cpu(i));
        qdev_connect_gpio_out(cpudev, GTIMER_VIRT,
                              qdev_get_gpio_in(s->gic,
                                  PCC_NUM_IRQS + i * GIC_INTERNAL + 27));
        sysbus_connect_irq(gicbusdev, i,
                           qdev_get_gpio_in(cpudev, ARM_CPU_IRQ));
        sysbus_connect_irq(gicbusdev, i + smp,
                           qdev_get_gpio_in(cpudev, ARM_CPU_FIQ));
    }
}

static void create_uart(VPhonePccMachine *s)
{
    DeviceState *dev = qdev_new(TYPE_PL011);
    SysBusDevice *sb = SYS_BUS_DEVICE(dev);

    qdev_prop_set_chr(dev, "chardev", serial_hd(0));
    sysbus_realize_and_unref(sb, &error_fatal);
    memory_region_add_subregion(get_system_memory(), 0x20010000,
                                sysbus_mmio_get_region(sb, 0));
    sysbus_connect_irq(sb, 0, qdev_get_gpio_in(s->gic, 1));
}

static void create_stubs(VPhonePccMachine *s)
{
    /* PL031 RTC, PL061 buttons, pvpanic, AES, AVP RTC/CTRR, SEP, GFX stubs. */
    sysbus_create_simple("pl031", 0x20050000, qdev_get_gpio_in(s->gic, 2));
    {
        DeviceState *pl061 = qdev_new("pl061");
        SysBusDevice *sb = SYS_BUS_DEVICE(pl061);
        qdev_prop_set_uint32(pl061, "pullups", 0);
        qdev_prop_set_uint32(pl061, "pulldowns", 0xff);
        sysbus_realize_and_unref(sb, &error_fatal);
        memory_region_add_subregion(get_system_memory(), 0x20060000,
                                    sysbus_mmio_get_region(sb, 0));
        sysbus_connect_irq(sb, 0, qdev_get_gpio_in(s->gic, 5));
    }
    create_unimplemented_device("pcc.pvpanic", 0x20070000, 0x1000);
    create_unimplemented_device("pcc.aes0", 0x30220000, 0x4000);
    create_unimplemented_device("pcc.aes1", 0x30230000, 0x4000);
    create_unimplemented_device("pcc.avp-rtc", 0x30240000, 0x1000);
    create_unimplemented_device("pcc.sep", 0x30250000, 0x100000);
    create_unimplemented_device("pcc.avp-ctrr", 0x30260000, 0x1000);
    /*
     * GFX / IOSurface mapper: leave the 0x10000 windows as unimplemented
     * stubs for the first boot. Reims apple-gfx-mmio (RVG_DEVICE_MMIO_SIZE
     * = 0x4000) plugs into the same bases later; DT regions are 0x10000 so
     * the extra 0xc000 is padding (confirmed against QEMU vmapple.c which
     * maps both at 0x10000).
     */
    create_unimplemented_device("pcc.apv-gfx", 0x30200000, 0x10000);
    create_unimplemented_device("pcc.apv-iosfc", 0x30210000, 0x10000);
}

static void create_pcie(VPhonePccMachine *s)
{
    DeviceState *dev = qdev_new(TYPE_GPEX_HOST);
    MemoryRegion *ecam_reg, *mmio_reg, *mmio_alias;
    int i;

    qdev_prop_set_uint32(dev, "num-irqs", 16);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    ecam_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0);
    memory_region_init_alias(&s->ecam_alias, OBJECT(dev), "pcie-ecam",
                             ecam_reg, 0, 0x10000000);
    memory_region_add_subregion(get_system_memory(), 0x40000000,
                                &s->ecam_alias);
    mmio_alias = g_new0(MemoryRegion, 1);
    mmio_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 1);
    memory_region_init_alias(mmio_alias, OBJECT(dev), "pcie-mmio",
                             mmio_reg, 0x50000000, 0x1fff0000);
    memory_region_add_subregion(get_system_memory(), 0x50000000, mmio_alias);
    for (i = 0; i < 16; i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(dev), i,
                           qdev_get_gpio_in(s->gic, 0x20 + i));
        gpex_set_irq_num(GPEX_HOST(dev), i, 0x20 + i);
    }
}

static void prepare_components(VPhonePccMachine *s, Error **errp)
{
    AppleModernBootMetadataInput mi = { 0 };
    const char *cl;

    for (int i = 0; i < A_COUNT; i++) {
        if (!s->paths[i]) {
            if (i == A_TC2 || i == A_RD) {
                continue; /* optional */
            }
            error_setg(errp, "vphone-pcc: required asset '%s' is missing",
                       asset_names[i]);
            return;
        }
        if (!read_asset(s->paths[i], &s->blobs[i], errp)) {
            return;
        }
    }

    s->components = (AppleModernBootInput){
        .bootkc = s->blobs[A_KC],
        .sptm = s->blobs[A_SPTM],
        .txm = s->blobs[A_TXM],
        .dtree = s->blobs[A_DT],
        .trustcache = s->blobs[A_TC],
        .cryptex_trustcache = s->blobs[A_TC2],
        .ramdisk = s->blobs[A_RD],
        .dram_base = PCC_DRAM_BASE,
        .dram_size = MACHINE(s)->ram_size,
        .trustcache_v2 = true,
        .platform_vmapple1 = true,
    };
    cl = s->command_line ? s->command_line :
         "serial=3 -v debug=0x2014e wdt=-1";
    mi.components = &s->components;
    mi.command_line = cl;
    mi.command_line_length = strlen(cl);
    mi.chosen_sepfw_absent = s->sepfw_absent;
    if (!apple_modern_boot_metadata_build(&mi, &s->metadata, errp)) {
        return;
    }
    warn_report("vphone-pcc: prepared layout platform=%s "
                "sptm_entry=0x%" PRIx64 " bootargs=0x%" PRIx64
                " dtree=0x%" PRIx64 " (%zu B)",
                s->metadata.layout.platform,
                s->metadata.layout.sptm_entry_physical,
                s->metadata.layout.bootargs_physical,
                s->metadata.layout.dtree_physical,
                s->metadata.dtree_size);
}

static void pcc_init(MachineState *machine)
{
    VPhonePccMachine *s = VPHONE_PCC_MACHINE(machine);
    Error *error = NULL;
    Object *cpu;

    prepare_components(s, &error);
    if (error) {
        error_report_err(error);
        exit(EXIT_FAILURE);
    }

    s->ram = machine->ram;
    memory_region_add_subregion(get_system_memory(), PCC_DRAM_BASE, s->ram);

    cpu = object_new(machine->cpu_type);
    object_property_add_child(OBJECT(s), "cpu", cpu);
    object_unref(cpu);
    s->cpu = ARM_CPU(cpu);
    object_property_set_bool(cpu, "has_el2", true, &error_fatal);
    object_property_set_bool(cpu, "has_el3", false, &error_fatal);
    object_property_set_bool(cpu, "pauth-noop", false, &error_fatal);
    /*
     * Full apple-modern CPU profile. APSTS_EL1 (s3_6_c15_c12_4) must reset
     * ready=1: SPTM polls its bit0 right after programming TCR/TTBR/MAIR
     * (see modern-apsts.c and the spin at VA 0xfffffff0270a75a4).
     */
    object_property_set_bool(cpu, "apple-modern-gxf", true, &error_fatal);
    object_property_set_bool(cpu, "apple-modern-timers", true, &error_fatal);
    object_property_set_bool(cpu, "apple-modern-guarded", true, &error_fatal);
    object_property_set_bool(cpu, "apple-modern-sprr", true, &error_fatal);
    object_property_set_bool(cpu, "apple-modern-apsts", true, &error_fatal);
    /*
     * sysregs: registration ORs ARM_CP_OVERRIDE and skips pauth/VMSA-owned
     * EL1 names (see arm_register_apple_modern_sysregs). Needed for
     * PREDAKEY* (s3_4_c15_c10_0..3) right after APCTL key setup.
     */
    object_property_set_bool(cpu, "apple-modern-sysregs", true, &error_fatal);
    object_property_set_bool(cpu, "apple-modern-pauth-compat", true,
                             &error_fatal);
    object_property_set_link(cpu, "memory", OBJECT(get_system_memory()),
                             &error_fatal);
    s->cpu->sme_vq.supported = 0x0b;
    qdev_realize(DEVICE(s->cpu), NULL, &error_fatal);

    create_gic(s);
    create_uart(s);
    create_stubs(s);
    create_pcie(s);

    qemu_register_reset(pcc_reset, s);
    s->initialized = true;
}

#define PATH_PROP(name, idx) \
static char *get_##name(Object *obj, Error **errp) \
{ \
    VPhonePccMachine *s = VPHONE_PCC_MACHINE(obj); \
    return g_strdup(s->paths[idx]); \
} \
static void set_##name(Object *obj, const char *value, Error **errp) \
{ \
    VPhonePccMachine *s = VPHONE_PCC_MACHINE(obj); \
    if (s->initialized) { \
        error_setg(errp, "vphone-pcc: cannot change %s after init", #name); \
        return; \
    } \
    g_free(s->paths[idx]); \
    s->paths[idx] = g_strdup(value); \
}

PATH_PROP(bootkc, A_KC)
PATH_PROP(sptm, A_SPTM)
PATH_PROP(txm, A_TXM)
PATH_PROP(dtree, A_DT)
PATH_PROP(tc, A_TC)
PATH_PROP(tc2, A_TC2)
PATH_PROP(ramdisk, A_RD)

static char *get_command_line(Object *obj, Error **errp)
{
    return g_strdup(VPHONE_PCC_MACHINE(obj)->command_line);
}
static void set_command_line(Object *obj, const char *value, Error **errp)
{
    VPhonePccMachine *s = VPHONE_PCC_MACHINE(obj);
    if (s->initialized) {
        error_setg(errp, "vphone-pcc: cannot change command-line after init");
        return;
    }
    g_free(s->command_line);
    s->command_line = g_strdup(value);
}

static bool get_prepare_only(Object *obj, Error **errp)
{
    return VPHONE_PCC_MACHINE(obj)->prepare_only;
}
static void set_prepare_only(Object *obj, bool value, Error **errp)
{
    VPHONE_PCC_MACHINE(obj)->prepare_only = value;
}
static bool get_sepfw_absent(Object *obj, Error **errp)
{
    return VPHONE_PCC_MACHINE(obj)->sepfw_absent;
}
static void set_sepfw_absent(Object *obj, bool value, Error **errp)
{
    VPHONE_PCC_MACHINE(obj)->sepfw_absent = value;
}

static void pcc_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->init = pcc_init;
    mc->max_cpus = 1;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("max");
    mc->default_ram_id = "vphone-pcc.ram";
    mc->desc = "PCC/vphone600ap direct loader (vmapple-class, TCG)";
    mc->no_cdrom = 1;

    object_class_property_add_str(oc, "bootkc", get_bootkc, set_bootkc);
    object_class_property_add_str(oc, "sptm", get_sptm, set_sptm);
    object_class_property_add_str(oc, "txm", get_txm, set_txm);
    object_class_property_add_str(oc, "dtree", get_dtree, set_dtree);
    object_class_property_add_str(oc, "tc", get_tc, set_tc);
    object_class_property_add_str(oc, "tc2", get_tc2, set_tc2);
    object_class_property_add_str(oc, "ramdisk", get_ramdisk, set_ramdisk);
    object_class_property_add_str(oc, "boot-command-line",
                                  get_command_line, set_command_line);
    object_class_property_add_bool(oc, "prepare-only",
                                   get_prepare_only, set_prepare_only);
    object_class_property_add_bool(oc, "sepfw-absent",
                                   get_sepfw_absent, set_sepfw_absent);
}

static const TypeInfo pcc_info = {
    .name = TYPE_VPHONE_PCC_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(VPhonePccMachine),
    .class_init = pcc_class_init,
};

static void pcc_register(void)
{
    type_register_static(&pcc_info);
}
type_init(pcc_register);
