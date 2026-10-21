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
#define SEP_MMIO_BASE   0x200000000ULL
#define SEP_MMIO_SIZE   0x100000000ULL
#define SEP_RAM_SIZE    (128ULL << 20)

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

static void sep_core_reset(void *opaque)
{
    AppleModernSEPCore *core = opaque;
    cpu_reset(CPU(core->cpu));
    cpu_set_pc(CPU(core->cpu), core->entry);
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
    core->entry = 0;
    if (len > core->ram_size) {
        error_setg(errp, "sep-core: image %zu bytes exceeds SEP RAM 0x%" PRIx64,
                   (size_t)len, core->ram_size);
        return false;
    }

    /* Private address space: RAM at 0 (image + work), catch-all MMIO aperture. */
    memory_region_init(&core->container, owner, "modern-sep.space", UINT64_MAX);
    memory_region_init_ram(&core->ram, NULL, "modern-sep.ram", core->ram_size,
                           &error_fatal);
    memory_region_add_subregion(&core->container, 0, &core->ram);
    memory_region_init_io(&core->mmio, owner, &sep_mmio_ops, core,
                          "modern-sep.mmio", SEP_MMIO_SIZE);
    memory_region_add_subregion(&core->container, SEP_MMIO_BASE, &core->mmio);
    memcpy(memory_region_get_ram_ptr(&core->ram), data, len);
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
    /* No apple-modern-sysregs here: it requires GXF (EL2) and defines the AP's
     * register set, not the SEP's. The SEP's own IMPDEF registers are modelled
     * separately (M2.2). */
    object_property_set_uint(cpuobj, "cntfrq", cntfrq, &error_fatal);
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
                "space (RAM 0x%" PRIx64 " at 0, MMIO 0x%" PRIx64 "); entry 0x%"
                PRIx64 ". M2.1: no AP mailbox wiring yet. Declared emulator "
                "bring-up, not Apple fidelity", cpu_type, image_path,
                (size_t)len, core->ram_size, (uint64_t)SEP_MMIO_BASE, core->entry);
    return true;
}
