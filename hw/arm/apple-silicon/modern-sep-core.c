/*
 * apple-modern SEP core: a second modern Apple CPU executing real (decrypted)
 * sepOS in its own private address space. Opt-in (sep-core), default off.
 *
 * This is NOT the firmware-free protocol simulator (sep-sim). It runs the
 * actual sepOS legion2 image on an Apple core so the SEP produces the real
 * SKS / xART / TXM-secure-channel protocol. M2.1 scope: stand the core up,
 * load the image, reset to its entry, and let it run in isolation (no AP
 * mailbox wiring yet). The SEP's own register map is discovered by booting
 * this under gdb; what it needs beyond the AP sysreg model is added over the
 * mmio catch-all (data) and the SEP IMPDEF sysreg set (later).
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "system/reset.h"
#include "target/arm/cpu.h"
#include "hw/arm/apple-silicon/modern-sep-core.h"

/* The SEP register aperture seen in early boot (read 0x2a0200000 config,
 * 0x2a0a0000c status, 0x2e42e41b8 boot-config; write 0x2a2140108 ctrl). A
 * single catch-all covers the whole 0x2_xxxxxxxx window; reads return 0
 * (which selects the cold-boot path), writes are logged and dropped. Specific
 * registers get real values here as boot reveals it needs them. */
#define SEP_MMIO_BASE          0x200000000ULL
#define SEP_MMIO_SIZE          0x100000000ULL
#define SEP_RAM_SIZE           (128ULL << 20)
#define SEP_SRAM_BASE          0x2a0200000ULL
#define SEP_SRAM_SIZE          0x400000ULL
#define SEP_BPSE_BASE          0x2a0210000ULL
#define SEP_DRAM_BASE          0x1e00000000ULL
#define SEP_DRAM_SIZE          0x80000000ULL
#define SEP_KRAM_BASE          0x1e40000000ULL
#define SEP_PFOUR_BASE         0x10000000000ULL
#define SEP_PFOUR_SIZE         0x1000000ULL
#define SEP_HANDOFF_B          0x84000000ULL
#define SEP_HANDOFF_SIZE_PAGES 4088
#define SEP_HANDOFF_COUNT      8
#define SEP_HANDOFF_R410       0x7000

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
    .valid = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
};

static uint64_t sep_pmgr_ps_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleModernSEPCore *core = opaque;
    uint8_t *p = memory_region_get_ram_ptr(&core->cfg0800) + 0x4000 + addr;
    uint64_t val = 0;

    if (addr + size <= 0x7c000) {
        memcpy(&val, p, size);
    }
    return val;
}

static void sep_pmgr_ps_write(void *opaque, hwaddr addr, uint64_t data,
                              unsigned size)
{
    AppleModernSEPCore *core = opaque;
    uint8_t *p = memory_region_get_ram_ptr(&core->cfg0800) + 0x4000 + addr;

    if (addr + size <= 0x7c000) {
        if (size == 4 && addr < 0x3c000 && (addr & 0x3fff) == 0) {
            uint32_t v = ((uint32_t)data & ~0x800000f0U) |
                         (((uint32_t)data & 0xfU) << 4);
            memcpy(p, &v, 4);
        } else {
            memcpy(p, &data, size);
        }
    }
}

static const MemoryRegionOps sep_pmgr_ps_ops = {
    .read = sep_pmgr_ps_read,
    .write = sep_pmgr_ps_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
};

static uint64_t sep_periph_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleModernSEPCore *core = opaque;
    uint8_t *p = memory_region_get_ram_ptr(&core->periph) + addr;
    uint64_t val = 0;

    if (addr + size <= 0x504000) {
        memcpy(&val, p, size);
    }
    return val;
}

static void sep_periph_write(void *opaque, hwaddr addr, uint64_t data,
                             unsigned size)
{
    AppleModernSEPCore *core = opaque;
    uint8_t *p = memory_region_get_ram_ptr(&core->periph) + addr;

    if (addr + size <= 0x504000) {
        if (addr == (0x2a0b80010ULL - 0x2a0b00000ULL) && size == 4) {
            uint32_t v = 0x101U;
            memcpy(p, &v, 4);
        } else if (addr == (0x2a0b80014ULL - 0x2a0b00000ULL) && size == 4) {
            uint32_t v = (uint32_t)data & ~0x8000U;
            memcpy(p, &v, 4);
        } else if (addr == (0x2a0e48000ULL - 0x2a0b00000ULL) && size == 4 &&
                   (uint32_t)data == 0xffffU) {
            uint32_t v = 0x50000U | 0xffffU;
            memcpy(p, &v, 4);
        } else {
            memcpy(p, &data, size);
        }
    }
}

static const MemoryRegionOps sep_periph_ops = {
    .read = sep_periph_read,
    .write = sep_periph_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
};

static void sep_core_reset(void *opaque)
{
    AppleModernSEPCore *core = opaque;
    cpu_reset(CPU(core->cpu));
    cpu_set_pc(CPU(core->cpu), core->entry);
    core->cpu->env.apple_modern_sep_store[14] = SEP_BPSE_BASE | 1;
    core->cpu->env.xregs[1] = SEP_KRAM_BASE;
}

bool apple_modern_sep_core_create(Object *owner, AppleModernSEPCore *core,
                                  const char *cpu_type, uint64_t cntfrq,
                                  const char *image_path, Error **errp)
{
    g_autofree char *data = NULL;
    gsize len = 0;
    Object *cpuobj;

    if (!image_path || !*image_path) {
        error_setg(errp, "sep-core needs sep-core-image=/path/to/decrypted/sepos");
        return false;
    }
    if (!g_file_get_contents(image_path, &data, &len, NULL)) {
        error_setg(errp, "sep-core: cannot read image '%s'", image_path);
        return false;
    }
    core->ram_size = SEP_RAM_SIZE;
    core->entry = SEP_KRAM_BASE;
    if (len < 0x4000 || len > core->ram_size) {
        error_setg(errp, "sep-core: image %zu bytes out of range for SEP RAM 0x%" PRIx64,
                   (size_t)len, core->ram_size);
        return false;
    }

    /* Private address space: SEP DRAM, SRAM, platform config, and peripherals. */
    memory_region_init(&core->container, owner, "modern-sep.space", UINT64_MAX);
    memory_region_init_ram(&core->ram, NULL, "modern-sep.ram", core->ram_size,
                           &error_fatal);
    memory_region_add_subregion(&core->container, 0, &core->ram);
    memory_region_init_io(&core->mmio, owner, &sep_mmio_ops, core,
                          "modern-sep.mmio", SEP_MMIO_SIZE);
    memory_region_add_subregion_overlap(&core->container, SEP_MMIO_BASE,
                                        &core->mmio, -10);

    memory_region_init_ram(&core->sram, NULL, "modern-sep.sram", SEP_SRAM_SIZE,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_SRAM_BASE,
                                        &core->sram, 0);
    memory_region_init_ram(&core->cfg0800, NULL, "modern-sep.cfg0800", 0x80000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2a0800000ULL,
                                        &core->cfg0800, 0);
    memory_region_init_io(&core->pmgr_ps_io, owner, &sep_pmgr_ps_ops, core,
                          "modern-sep.pmgr-ps", 0x7c000);
    memory_region_add_subregion_overlap(&core->container, 0x2a0804000ULL,
                                        &core->pmgr_ps_io, 1);
    memory_region_init_ram(&core->periph, NULL, "modern-sep.periph", 0x504000,
                           &error_fatal);
    memory_region_init_io(&core->periph_io, owner, &sep_periph_ops, core,
                          "modern-sep.periph-io", 0x504000);
    memory_region_add_subregion_overlap(&core->container, 0x2a0b00000ULL,
                                        &core->periph_io, 0);
    memory_region_init_ram(&core->cfg0c40, NULL, "modern-sep.cfg0c40", 0x10000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2a0c40000ULL,
                                        &core->cfg0c40, 1);
    memory_region_init_ram(&core->fuse, NULL, "modern-sep.fuse", 0x30000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2e42c0000ULL,
                                        &core->fuse, 0);
    memory_region_init_ram(&core->sepmmio, NULL, "modern-sep.sepmmio", 0x1000000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2a2000000ULL,
                                        &core->sepmmio, 0);
    memory_region_init_ram(&core->dram, NULL, "modern-sep.dram", SEP_DRAM_SIZE,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_DRAM_BASE,
                                        &core->dram, 0);
    memory_region_init_ram(&core->pfour, NULL, "modern-sep.pfour",
                           SEP_PFOUR_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_PFOUR_BASE,
                                        &core->pfour, 0);

    {
        uint8_t *cfg0800 = memory_region_get_ram_ptr(&core->cfg0800);
        uint8_t *cfg0c40 = memory_region_get_ram_ptr(&core->cfg0c40);
        uint8_t *periph = memory_region_get_ram_ptr(&core->periph);
        uint8_t *xprt = memory_region_get_ram_ptr(&core->fuse);
        uint32_t *fz = (uint32_t *)(xprt + 0x8000);
        uint8_t *mmio = memory_region_get_ram_ptr(&core->sepmmio);
        uint8_t *sram = memory_region_get_ram_ptr(&core->sram);
        uint8_t *bpse = sram + (SEP_BPSE_BASE - SEP_SRAM_BASE);
        uint8_t *pf = memory_region_get_ram_ptr(&core->pfour);
        const struct {
            char tag[4];
            uint32_t size;
            uint64_t off;
        } plat_cfg[] = {
            { { 'S', 'N', 'O', 'C' }, 0x4000, 0x04000 },
            { { 'E', 'R', 'O', 'C' }, 0x4000, 0x08000 },
            { { 'T', 'U', 'P', 'C' }, 0x4000, 0x0c000 },
            { { 'C', 'I', 'N', 'P' }, 0x8000, 0x10000 },
            { { 'C', 'A', 'R', 'T' }, 0x4000, 0x18000 },
            { { 'l', 'l', 'u', 'n' }, 0, 0 },
        };

        memcpy(bpse, data, 0x4000);
        *(uint32_t *)(bpse + 0x00) = 0x53455042;
        *(uint32_t *)(bpse + 0x08) = 1;
        *(uint32_t *)(bpse + 0x70) = len;
        *(uint32_t *)(bpse + 0x78) = 0x4000;
        *(uint64_t *)(bpse + 0x80) = 0x0123456789abcdefULL;
        *(uint64_t *)(bpse + 0x88) = 0xfedcba9876543210ULL;

        *(uint32_t *)(cfg0800 + 0x408) = (SEP_HANDOFF_B >> 12) - 1;
        *(uint32_t *)(cfg0800 + 0x410) = SEP_HANDOFF_R410;
        *(uint32_t *)(cfg0800 + 0x418) = SEP_HANDOFF_R410;
        *(uint32_t *)(cfg0800 + 0x8000) = 0x44;
        *(uint32_t *)(cfg0800 + 0xc000) = 0x44;
        *(uint32_t *)(cfg0800 + 0x14000) = 0x44;
        *(uint32_t *)(cfg0800 + 0x20000) = 0x44;
        *(uint32_t *)(cfg0800 + 0x2c000) = 0x44;
        *(uint32_t *)(cfg0c40 + 0x180) = SEP_HANDOFF_COUNT;
        *(uint32_t *)(cfg0c40 + 0x1a0) = SEP_HANDOFF_SIZE_PAGES;

        *(uint32_t *)(periph + (0x2a0b80000ULL - 0x2a0b00000ULL)) = 0x34fbf246;
        *(uint32_t *)(periph + (0x2a0b80004ULL - 0x2a0b00000ULL)) = 0xb40a6f2d;
        *(uint32_t *)(periph + (0x2a0b80008ULL - 0x2a0b00000ULL)) = 0xc56f4777;
        *(uint32_t *)(periph + (0x2a0b8000cULL - 0x2a0b00000ULL)) = 0x5f2c2401;
        *(uint32_t *)(periph + (0x2a0b80010ULL - 0x2a0b00000ULL)) = 0x101;
        *(uint32_t *)(periph + (0x2a0b80078ULL - 0x2a0b00000ULL)) = 0x00180000;
        *(uint32_t *)(periph + (0x2a0b8007cULL - 0x2a0b00000ULL)) = 0x02000000;
        *(uint32_t *)(periph + (0x2a0bc1800ULL - 0x2a0b00000ULL)) = 0x3;
        *(uint32_t *)(periph + (0x2a0dc0010ULL - 0x2a0b00000ULL)) = 0x101;
        *(uint32_t *)(periph + (0x2a0dd8008ULL - 0x2a0b00000ULL)) = 0xa55ac33c;
        *(uint32_t *)(periph + (0x2a0e40400ULL - 0x2a0b00000ULL)) = 0xa55ac33c;
        *(uint32_t *)(periph + (0x2a0e40410ULL - 0x2a0b00000ULL)) = 0xa55ac33c;
        *(uint32_t *)(periph + (0x2a0e48000ULL - 0x2a0b00000ULL)) = 0x40000;
        *(uint32_t *)(periph + (0x2a0e4c000ULL - 0x2a0b00000ULL)) = 0x5;
        *(uint32_t *)(periph + (0x2a0e50008ULL - 0x2a0b00000ULL)) = 0x5;
        *(uint32_t *)(periph + (0x2a0e50010ULL - 0x2a0b00000ULL)) = 0x4;
        *(uint32_t *)(periph + (0x2a1000000ULL - 0x2a0b00000ULL)) = 0xa55ac33c;
        *(uint32_t *)(periph + (0x2a1000008ULL - 0x2a0b00000ULL)) = 0xa55ac33c;

        *(uint32_t *)(xprt + 0x4000) = 0x32b3;
        fz[0] = 0xa55ac33c;
        fz[1] = 0xa55ac33c;
        fz[2] = 0xa55ac33c;
        fz[3] = 0xa55ac33c;
        fz[0x900 / 4] = 0xa55ac33c;
        fz[0x904 / 4] = 0xa55ac33c;
        fz[0x908 / 4] = 0xa55ac33c;
        fz[0x90c / 4] = 0xa55ac33c;
        for (unsigned i = 0; i < 8; i++) {
            fz[(0x9b0 + i * 4) / 4] = 0xa55ac33c;
        }

        *(uint64_t *)(mmio + (0x2a2404810ULL - 0x2a2000000ULL)) =
            (uint64_t)(SEP_PFOUR_BASE >> 12) << 32 |
            (uint64_t)(0x400000 >> 12) << 16 | 0xfe;

        for (unsigned i = 0; i < ARRAY_SIZE(plat_cfg); i++) {
            uint32_t tag = plat_cfg[i].tag[0] |
                           plat_cfg[i].tag[1] << 8 |
                           plat_cfg[i].tag[2] << 16 |
                           (uint32_t)plat_cfg[i].tag[3] << 24;
            uint64_t *e = (uint64_t *)(pf + i * 0x10);
            e[0] = tag | ((uint64_t)plat_cfg[i].size << 32);
            e[1] = plat_cfg[i].off;
        }
    }

    memcpy(memory_region_get_ram_ptr(&core->ram), data, len);
    memcpy(memory_region_get_ram_ptr(&core->dram) +
               (SEP_KRAM_BASE - SEP_DRAM_BASE), data, len);
    address_space_init(&core->as, &core->container, "modern-sep");

    /* A second modern Apple core, configured as the AP cores are (Apple
     * sysregs + PAC), but with this private memory and no SMP/AIC role. */
    cpuobj = object_new(cpu_type);
    core->cpu = ARM_CPU(cpuobj);
    object_property_add_child(owner, "sep-cpu", cpuobj);
    object_unref(cpuobj);
    /* sepOS is EL1 code (sets VBAR_EL1/TTBR1_EL1). The core must RESET at EL1,
     * so no EL2/EL3. GXF/SPRR/guarded/APSTS are AP-kernel features sepOS does
     * not use; only the Apple IMPDEF sysreg infrastructure is kept. PAC is
     * real (QEMU `max` models the Apple PAC keys). */
    object_property_set_bool(cpuobj, "has_el2", false, &error_fatal);
    object_property_set_bool(cpuobj, "has_el3", false, &error_fatal);
    object_property_set_bool(cpuobj, "pauth-noop", false, &error_fatal);
    /* Model the SEP's own IMPDEF system registers (read-as-written; not GXF-gated). */
    object_property_set_bool(cpuobj, "apple-modern-sep", true, &error_fatal);
    /* No apple-modern-sysregs here: it requires GXF (EL2) and defines the AP's
     * register set, not the SEP's. The SEP's own IMPDEF registers are modelled
     * separately (M2.2). */
    object_property_set_uint(cpuobj, "cntfrq", cntfrq ? cntfrq : 24000000,
                             &error_fatal);
    object_property_set_uint(cpuobj, "rvbar", core->entry, &error_fatal);
    object_property_set_link(cpuobj, "memory", OBJECT(&core->container),
                             &error_fatal);
    /* Cap SME streaming vector length as the AP cores do. */
    core->cpu->sme_vq.supported = 0x0b;
    if (!qdev_realize(DEVICE(core->cpu), NULL, errp)) {
        return false;
    }
    qemu_register_reset(sep_core_reset, core);

    warn_report("apple-modern: opt-in SEP CORE: a second Apple '%s' core runs "
                "the real sepOS image '%s' (%zu bytes) in a private address "
                "space (DRAM 0x%" PRIx64 ", SRAM 0x%" PRIx64 ", MMIO 0x%" PRIx64
                "); entry 0x%" PRIx64 ". Declared emulator bring-up, not Apple "
                "fidelity", cpu_type, image_path, (size_t)len,
                (uint64_t)SEP_DRAM_BASE, (uint64_t)SEP_SRAM_BASE,
                (uint64_t)SEP_MMIO_BASE, core->entry);
    return true;
}
