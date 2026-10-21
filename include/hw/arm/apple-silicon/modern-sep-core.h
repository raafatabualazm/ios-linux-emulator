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
    MemoryRegion ram;         /* SEP SRAM at 0: sepOS image + working memory  */
    MemoryRegion mmio;        /* catch-all for the SEP register aperture      */
    uint64_t ram_size;
    uint64_t entry;           /* reset PC (legion2 entry; 0)                  */
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
