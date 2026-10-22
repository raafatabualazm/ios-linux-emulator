/*
 * apple-modern SEP core: a second modern Apple CPU executing real (decrypted)
 * sepOS in its own address space. Opt-in, default off. See modern-sep-core.c.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef HW_ARM_APPLE_MODERN_SEP_CORE_H
#define HW_ARM_APPLE_MODERN_SEP_CORE_H

#include "qemu/osdep.h"
#include "system/memory.h"
#include "target/arm/cpu-qom.h"
#include "hw/irq.h"

/*
 * SEPROM-equivalent handoff (lab-proven on apple-sep-lab,seprom=on): BPSE
 * boot-args, memory-config regs, fuse sentinels, 24 MHz cntfrq, and the
 * kernel image loaded at the SEP RAM carveout PA 0x1e40000000. Synthetic
 * identity — research vehicle for the AP-facing protocol, not a faithful
 * D47 SEP. Gated behind sep-core=on (itself default off).
 */
#define SEP_CORE_KRAM_BASE      0x1e40000000ULL
#define SEP_CORE_KRAM_SIZE      0x10000000ULL   /* 256 MiB */
#define SEP_CORE_SRAM_BASE      0x2a0200000ULL
#define SEP_CORE_SRAM_SIZE      0x400000ULL     /* 4 MiB */
#define SEP_CORE_CARVEOUT_BASE  0x2a4000000ULL
#define SEP_CORE_CARVEOUT_SIZE  0x10000000ULL   /* 256 MiB */
#define SEP_CORE_BPSE_ADDR      0x2a0210000ULL
#define SEP_CORE_FUSE_BASE      0x2e42c8000ULL
#define SEP_CORE_SEPMMIO_BASE   0x2a2000000ULL
#define SEP_CORE_SEPMMIO_SIZE   0x1000000ULL    /* 16 MiB */
#define SEP_CORE_CNTFRQ         24000000ULL

typedef struct AppleModernSEPCore {
    ARMCPU *cpu;
    AddressSpace as;
    MemoryRegion container;   /* root of the SEP CPU's private address space */
    MemoryRegion ram;         /* small lab RAM at PA 0 (legacy / debug)       */
    MemoryRegion kram;        /* SEP kernel RAM carveout: image + page tables */
    MemoryRegion sram;        /* SEP SRAM (stack/data) at 0x2a0200000         */
    MemoryRegion carveout;    /* SEP DRAM reported by memory-config regs      */
    MemoryRegion cfg0800;     /* memory-config page 0x2a0800000               */
    MemoryRegion cfg0c40;     /* memory-config page 0x2a0c40000               */
    MemoryRegion fuse;        /* security-fuse shadow 0x2e42c8000             */
    MemoryRegion sepmmio;     /* pokeable SEP MMIO swath 0x2a2000000          */
    MemoryRegion mmio;        /* catch-all for remaining 0x2_xxxxxxxx         */
    qemu_irq sep_irq;         /* SEP cpu ARM_CPU_IRQ (for future ASC-v6)      */
    uint64_t ram_size;
    uint64_t entry;           /* reset PC = SEP_CORE_KRAM_BASE                */
    bool seprom_handoff;      /* true once handoff RAM/sysregs seeded         */
} AppleModernSEPCore;

/*
 * Create and realize the SEP core with the lab-proven SEPROM handoff so
 * sepOS reaches kernel-main / platform-init on the private core without
 * gdb pokes. `cntfrq` from the AP is ignored; the SEP timebase is forced
 * to 24 MHz. Returns false with errp set on failure.
 */
bool apple_modern_sep_core_create(Object *owner, AppleModernSEPCore *core,
                                  const char *cpu_type, uint64_t cntfrq,
                                  const char *image_path, Error **errp);

#endif /* HW_ARM_APPLE_MODERN_SEP_CORE_H */
