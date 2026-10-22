/*
 * apple-modern SEP core: a second modern Apple CPU executing real (decrypted)
 * sepOS in its own private address space. Opt-in (sep-core), default off.
 *
 * This is NOT the firmware-free protocol simulator (sep-sim). It runs the
 * actual sepOS legion2 image on an Apple core so the SEP can produce the real
 * SKS / xART / TXM-secure-channel protocol. Scope here (M2.5 port): stand the
 * core up with the lab-proven SEPROM handoff so sepOS boots through
 * parse → page-tables → MMU → kernel-main into platform init on its own,
 * without gdb pokes. AP mailbox wiring (M3) is separate.
 *
 * Framing: Corellium-style sepOS-only research on the J410 (A17) image for
 * build 24A437. Synthetic identity (fuses / memory map). Not a faithful D47
 * SEP and not a key-unwrapping vehicle for an existing warm keybag.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/irq.h"
#include "system/reset.h"
#include "target/arm/cpu.h"
#include "hw/arm/apple-silicon/modern-sep-core.h"

/* Catch-all for the remaining 0x2_xxxxxxxx aperture after specific RAM pages
 * are overlaid at higher priority. Reads return 0; writes are logged. */
#define SEP_MMIO_BASE   0x200000000ULL
#define SEP_MMIO_SIZE   0x100000000ULL
#define SEP_RAM_AT_ZERO (16ULL << 20) /* small PA-0 lab RAM; image lives in kram */

/* Boot-role sysreg index in CPUARMState.apple_modern_sep_store[]
 * (s3_7_c15_c2_6). Bit0 = present; odd & >1 selects the cold build path. */
#define SEP_BOOT_ROLE_STORE_IDX 14

static uint64_t sep_mmio_read(void *opaque, hwaddr offset, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "modern-sep-core: MMIO read  0x%" PRIx64
                  " size %u -> 0\n", (uint64_t)(SEP_MMIO_BASE + offset), size);
    return 0;
}

static void sep_mmio_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "modern-sep-core: MMIO write 0x%" PRIx64
                  " size %u value 0x%" PRIx64 "\n",
                  (uint64_t)(SEP_MMIO_BASE + offset), size, value);
}

static const MemoryRegionOps sep_mmio_ops = {
    .read = sep_mmio_read,
    .write = sep_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

/*
 * Seed the SEPROM handoff the lab reversed (BOOT-RE.md / apple-sep-lab seprom):
 * BPSE boot-args, memory-config regs, fuse sentinels, region encode. Called at
 * create and again from reset so a soft reset restores the contract (RAM
 * contents persist, but boot-role resets to 0 with the CP resetvalue).
 */
static void sep_core_seed_handoff(AppleModernSEPCore *core)
{
    uint32_t *sram;
    uint32_t *cfg0800;
    uint32_t *cfg0c40;
    uint32_t *fuse;
    uint32_t *sepmmio;

    /* BPSE boot-args in SEP SRAM. */
    sram = memory_region_get_ram_ptr(&core->sram);
    /* BPSE lives at absolute PA SEP_CORE_BPSE_ADDR inside the SRAM window. */
    {
        uint32_t *bpse = (uint32_t *)((uint8_t *)sram +
                                      (SEP_CORE_BPSE_ADDR - SEP_CORE_SRAM_BASE));
        bpse[0] = 0x53455042;                 /* "BPSE" */
        bpse[2] = 1;                          /* [+8] = 1 */
        bpse[0x70 / 4] = 0x528000;            /* [+0x70] memory size */
    }

    cfg0800 = memory_region_get_ram_ptr(&core->cfg0800);
    cfg0800[0x408 / 4] = 0x2a3fff;            /* base = (v<<12)+0x1000 = carveout */
    cfg0800[0x410 / 4] = 0;
    cfg0800[0x418 / 4] = 0;

    cfg0c40 = memory_region_get_ram_ptr(&core->cfg0c40);
    cfg0c40[0x180 / 4] = 4;
    cfg0c40[0x1a0 / 4] = 0x4000;              /* (0x4000-4) divisible by 10 */

    fuse = memory_region_get_ram_ptr(&core->fuse);
    fuse[0] = 0xa55ac33c;                     /* secfuse.c:52 sentinels */
    fuse[1] = 0xa55ac33c;

    /* Region encode at 0x2a2404810/4814: type 0xfe, size 0x400000 pages<<12,
     * base 0x10000000000 >> 12. Contained in the synthetic table[2] the
     * build path constructs from these handoff values (see BOOT-RE M2.6). */
    sepmmio = memory_region_get_ram_ptr(&core->sepmmio);
    sepmmio[0x404810 / 4] = 0x040000fe;
    sepmmio[0x404814 / 4] = 0x10000000;

    /* Boot-role = BPSE | 1 (present, odd → cold build path). cpu_reset restores
     * the CP resetvalue (0), so this must run after every cpu_reset. */
    core->cpu->env.apple_modern_sep_store[SEP_BOOT_ROLE_STORE_IDX] =
        SEP_CORE_BPSE_ADDR | 1ULL;

    /* Ready bit (s3_6_c15_c12_4) must stay 1 across reset. */
    core->cpu->env.apple_modern_sep_store[13] = 1ULL;

    core->seprom_handoff = true;
}

static void sep_core_reset(void *opaque)
{
    AppleModernSEPCore *core = opaque;

    cpu_reset(CPU(core->cpu));
    cpu_set_pc(CPU(core->cpu), core->entry);
    /* cpu_reset cleared boot-role / ready to their CP resetvalues — reseed. */
    sep_core_seed_handoff(core);
}

bool apple_modern_sep_core_create(Object *owner, AppleModernSEPCore *core,
                                  const char *cpu_type, uint64_t cntfrq,
                                  const char *image_path, Error **errp)
{
    g_autofree char *data = NULL;
    gsize len = 0;
    Object *cpuobj;
    (void)cntfrq; /* SEP timebase is forced to 24 MHz; AP value is irrelevant. */

    if (!image_path || !*image_path) {
        error_setg(errp, "sep-core needs sep-core-image=/path/to/decrypted/sepos");
        return false;
    }
    if (!g_file_get_contents(image_path, &data, &len, NULL)) {
        error_setg(errp, "sep-core: cannot read image '%s'", image_path);
        return false;
    }
    if (len > SEP_CORE_KRAM_SIZE) {
        error_setg(errp, "sep-core: image %zu bytes exceeds SEP KRAM 0x%" PRIx64,
                   (size_t)len, (uint64_t)SEP_CORE_KRAM_SIZE);
        return false;
    }
    core->ram_size = SEP_RAM_AT_ZERO;
    /* Run from the SEP RAM carveout: VA 0xffffffff00000000 → PA 0x1e40000000. */
    core->entry = SEP_CORE_KRAM_BASE;

    memory_region_init(&core->container, owner, "modern-sep.space", UINT64_MAX);

    /* PA 0 lab RAM (debug / unused by seprom path). */
    memory_region_init_ram(&core->ram, NULL, "modern-sep.ram0", core->ram_size,
                           &error_fatal);
    memory_region_add_subregion(&core->container, 0, &core->ram);

    /* Catch-all MMIO at low priority; specific RAM pages overlay it. */
    memory_region_init_io(&core->mmio, owner, &sep_mmio_ops, core,
                          "modern-sep.mmio", SEP_MMIO_SIZE);
    memory_region_add_subregion_overlap(&core->container, SEP_MMIO_BASE,
                                        &core->mmio, -100);

    /* SEP kernel RAM: image + page-table pool (BSS of the image is zero). */
    memory_region_init_ram(&core->kram, NULL, "modern-sep.kram",
                           SEP_CORE_KRAM_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_KRAM_BASE,
                                        &core->kram, 0);
    memcpy(memory_region_get_ram_ptr(&core->kram), data, len);

    /* SEP SRAM (stack at 0x2a0220000, BPSE at 0x2a0210000). */
    memory_region_init_ram(&core->sram, NULL, "modern-sep.sram",
                           SEP_CORE_SRAM_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_SRAM_BASE,
                                        &core->sram, 0);

    /* Carveout the memory-config regs advertise. */
    memory_region_init_ram(&core->carveout, NULL, "modern-sep.carveout",
                           SEP_CORE_CARVEOUT_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_CARVEOUT_BASE,
                                        &core->carveout, 0);

    memory_region_init_ram(&core->cfg0800, NULL, "modern-sep.cfg0800", 0x10000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2a0800000ULL,
                                        &core->cfg0800, 0);
    memory_region_init_ram(&core->cfg0c40, NULL, "modern-sep.cfg0c40", 0x10000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2a0c40000ULL,
                                        &core->cfg0c40, 0);

    memory_region_init_ram(&core->fuse, NULL, "modern-sep.fuse", 0x10000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_FUSE_BASE,
                                        &core->fuse, 0);

    memory_region_init_ram(&core->sepmmio, NULL, "modern-sep.sepmmio",
                           SEP_CORE_SEPMMIO_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_SEPMMIO_BASE,
                                        &core->sepmmio, 0);

    address_space_init(&core->as, &core->container, "modern-sep");

    cpuobj = object_new(cpu_type);
    core->cpu = ARM_CPU(cpuobj);
    object_property_add_child(owner, "sep-cpu", cpuobj);
    object_unref(cpuobj);
    /* sepOS is EL1 (VBAR_EL1 / TTBR1_EL1). Reset at EL1: no EL2/EL3. */
    object_property_set_bool(cpuobj, "has_el2", false, &error_fatal);
    object_property_set_bool(cpuobj, "has_el3", false, &error_fatal);
    object_property_set_bool(cpuobj, "pauth-noop", false, &error_fatal);
    object_property_set_bool(cpuobj, "apple-modern-sep", true, &error_fatal);
    /* Force the SEP 24 MHz timebase (timer.c:19). */
    object_property_set_uint(cpuobj, "cntfrq", SEP_CORE_CNTFRQ, &error_fatal);
    object_property_set_uint(cpuobj, "rvbar", core->entry, &error_fatal);
    object_property_set_link(cpuobj, "memory", OBJECT(&core->container),
                             &error_fatal);
    core->cpu->sme_vq.supported = 0x0b;
    if (!qdev_realize(DEVICE(core->cpu), NULL, errp)) {
        return false;
    }
    core->sep_irq = qdev_get_gpio_in(DEVICE(core->cpu), ARM_CPU_IRQ);

    /* Seed handoff before first reset so a cold start is gdb-free. */
    sep_core_seed_handoff(core);
    qemu_register_reset(sep_core_reset, core);

    warn_report("apple-modern: opt-in SEP CORE + SEPROM handoff: '%s' core runs "
                "sepOS '%s' (%zu bytes) from PA 0x%" PRIx64 " (kram); BPSE@"
                "0x%" PRIx64 ", fuse@0x%" PRIx64 ", cntfrq=%" PRIu64 ", boot-role="
                "BPSE|1. Synthetic identity; no AP mailbox yet (M3). Declared "
                "emulator bring-up, not Apple fidelity",
                cpu_type, image_path, (size_t)len,
                (uint64_t)SEP_CORE_KRAM_BASE, (uint64_t)SEP_CORE_BPSE_ADDR,
                (uint64_t)SEP_CORE_FUSE_BASE, (uint64_t)SEP_CORE_CNTFRQ);
    return true;
}
