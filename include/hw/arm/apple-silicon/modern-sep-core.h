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

typedef struct AppleModernSEPCore {
    ARMCPU *cpu;
    AddressSpace as;
    MemoryRegion container;   /* root of the SEP CPU's private address space */
    MemoryRegion ram;         /* legacy low RAM alias                        */
    MemoryRegion mmio;        /* catch-all for the SEP register aperture      */
    MemoryRegion sram;        /* SEP SRAM 0x2a0200000 (stack + BPSE handoff) */
    MemoryRegion dram;        /* SEP DRAM 0x1e00000000 (kernel @ 0x1e40000000) */
    MemoryRegion pfour;       /* SEP platform config window 0x10000000000    */
    MemoryRegion cfg0800;     /* SEP PMGR + memcfg 0x2a0800000 (512 KiB)     */
    MemoryRegion pmgr_ps_io;  /* PMGR power-state auto-latch at +0x4000      */
    MemoryRegion periph;      /* SEP peripheral backing 0x2a0b00000..        */
    MemoryRegion periph_io;   /* SEP peripheral MMIO ops 0x2a0b00000..       */
    MemoryRegion cfg0c40;     /* SEP memory-config 0x2a0c40000               */
    MemoryRegion fuse;        /* SEP XPRT + fuse blocks 0x2e42c0000          */
    MemoryRegion sepmmio;     /* SEP MMIO / AKF block 0x2a2000000            */
    uint64_t ram_size;
    uint64_t entry;           /* reset PC (0x1e40000000)                     */
} AppleModernSEPCore;

/*
 * Create and realize the SEP core: a `max` ARM CPU configured like the AP
 * cores (Apple modern sysregs + PAC), but with a private address space that
 * holds the sepOS image at `entry` and a catch-all MMIO aperture. The image
 * bytes are copied into SEP RAM at offset 0. Returns false with errp set on
 * failure. `cpu_type` is the machine cpu_type ("max"); `cntfrq` the timebase.
 */
bool apple_modern_sep_core_create(Object *owner, AppleModernSEPCore *core,
                                  const char *cpu_type, uint64_t cntfrq,
                                  const char *image_path, Error **errp);

#endif /* HW_ARM_APPLE_MODERN_SEP_CORE_H */
