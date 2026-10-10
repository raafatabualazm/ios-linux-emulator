/*
 * T8140 /arm-io/disp0 unified display pipe — declared, default-off skeleton.
 *
 * Copyright (c) 2023-2026 Visual Ehrmanntraut (VisualEhrmanntraut).
 * Copyright (c) 2023-2026 Christian Inci (chris-pcguy).
 * Copyright (c) 2026 the Inferno-and-Darwin-VM project.
 *
 * The register layout, the GenPipe/Blend block taxonomy and the console
 * scanout half of this device are derived from the AGPL-3.0 A13/t8030 model
 * hw/display/apple_displaypipe_v4.c by the authors named above, which is part
 * of this same repository. Only the T8140 window plan, the shadow-stride
 * generalisation, the faulting decode and the gates are new here.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef HW_ARM_APPLE_MODERN_DISP0_H
#define HW_ARM_APPLE_MODERN_DISP0_H
#include "hw/arm/apple-silicon/modern-board-regions.h"

/* /arm-io/disp0 carries exactly six reg windows and nine interrupts on both
 * t8030 (A13) and t8140 (A18 Pro) — measured from the two stock ADTs. */
#define APPLE_MODERN_DISP0_WINDOWS 6
#define APPLE_MODERN_DISP0_IRQS 9

/* Window 0 is the pipe register aperture. On t8030 it is 0x2fc000 bytes and
 * the ChefKiss model folds any offset >= 0x200000 down by 0x200000; on t8140
 * it is 0xafc000. Both decompose exactly as k * 0x200000 + 0xfc000 (k = 1 and
 * k = 5), so the block map is 0xfc000 wide and the aperture carries k shadow
 * aliases of it at multiples of 0x200000. The 0xfc000 figure is ATTESTED for
 * neither part; it is ARITHMETIC on two attested window sizes, and the k = 5
 * generalisation is DECLARED-INFERRED. */
#define APPLE_MODERN_DISP0_SHADOW_STRIDE 0x200000
#define APPLE_MODERN_DISP0_BLOCK_SPAN 0xfc000

/* Block bases inside the folded aperture. ANALOGY: every one of these is the
 * t8030 value out of apple_displaypipe_v4.c. None is attested for t8140. */
#define APPLE_MODERN_DISP0_GP_BASE 0x50000
#define APPLE_MODERN_DISP0_GP_BLOCK_STRIDE 0x8000
#define APPLE_MODERN_DISP0_GP_COUNT 2
#define APPLE_MODERN_DISP0_BLEND_BASE 0x60000
#define APPLE_MODERN_DISP0_BLEND_SPAN 0x8000
#define APPLE_MODERN_DISP0_LAYERS 2

/* Control block registers (ANALOGY, t8030 offsets). */
#define APPLE_MODERN_DISP0_INT_STATUS 0x45818
#define APPLE_MODERN_DISP0_INT_ENABLE 0x4581c
#define APPLE_MODERN_DISP0_VERSION 0x46020
#define APPLE_MODERN_DISP0_KICK 0x4602c
#define APPLE_MODERN_DISP0_FRAME_SIZE 0x4603c
#define APPLE_MODERN_DISP0_KICK_BIT 12

/* Interrupt bits of the control block (ANALOGY, t8030 field positions). */
#define APPLE_MODERN_DISP0_INT_OUTPUT_READY (1u << 10)
#define APPLE_MODERN_DISP0_INT_FRAME_PROCESSED (1u << 20)

/* GenPipe registers, relative to the GenPipe block base (ANALOGY). */
#define APPLE_MODERN_DISP0_GP_CONFIG 0x4
#define APPLE_MODERN_DISP0_GP_PIXFMT 0x1c
#define APPLE_MODERN_DISP0_GP_DATA_START 0x30
#define APPLE_MODERN_DISP0_GP_DATA_END 0x40
#define APPLE_MODERN_DISP0_GP_STRIDE 0x60
#define APPLE_MODERN_DISP0_GP_SRC_DIMS 0x70
#define APPLE_MODERN_DISP0_GP_DEST_DIMS 0x80
#define APPLE_MODERN_DISP0_GP_CONFIG_RUN (1u << 0)
#define APPLE_MODERN_DISP0_GP_CONFIG_ENABLED (1u << 31)
#define APPLE_MODERN_DISP0_GP_PIXFMT_COMPRESSED (1u << 30)

/* Blend unit registers, relative to the blend block base (ANALOGY). */
#define APPLE_MODERN_DISP0_BLEND_LAYER0 0x14
#define APPLE_MODERN_DISP0_BLEND_LAYER1 0x18

/* How many distinct faulting accesses a run remembers for the frontier
 * report. A run that overflows this still counts every fault. */
#define APPLE_MODERN_DISP0_FRONTIER_SLOTS 32

typedef enum {
    APPLE_MODERN_DISP0_WINDOW_PIPE = 0, /* modelled: the pipe aperture */
    APPLE_MODERN_DISP0_WINDOW_OPAQUE,   /* mapped, no register modelled */
    APPLE_MODERN_DISP0_WINDOW_DCP,      /* contains /arm-io/dcp: not ours */
    APPLE_MODERN_DISP0_WINDOW_PMGR,     /* inside /arm-io/pmgr: not ours */
} AppleModernDisp0WindowKind;

typedef struct AppleModernDisp0Window {
    uint64_t address;
    uint64_t size;
    uint32_t kind; /* AppleModernDisp0WindowKind */
    uint32_t mapped;
} AppleModernDisp0Window;

typedef struct AppleModernDisp0Plan {
    AppleModernDisp0Window windows[APPLE_MODERN_DISP0_WINDOWS];
    uint32_t interrupts[APPLE_MODERN_DISP0_IRQS];
    uint32_t shadow_copies; /* k above: 1 on t8030, 5 on t8140 */
    uint32_t dot_pitch;
    uint32_t mapped_count;
} AppleModernDisp0Plan;

typedef struct AppleModernDisp0GenPipe {
    uint32_t config;
    uint32_t pixel_format;
    uint32_t data_start;
    uint32_t data_end;
    uint32_t stride;
    uint16_t src_width, src_height;
    uint16_t dest_width, dest_height;
} AppleModernDisp0GenPipe;

typedef struct AppleModernDisp0Frontier {
    uint64_t address;
    uint32_t offset;   /* folded offset inside the window */
    uint8_t window;
    uint8_t size;
    uint8_t is_write;
    uint8_t valid;
} AppleModernDisp0Frontier;

typedef struct AppleModernDisp0Core {
    AppleModernDisp0Plan plan;
    uint32_t width, height;
    uint32_t version;
    uint32_t int_status, int_enable;
    uint32_t blend_layer[APPLE_MODERN_DISP0_LAYERS];
    AppleModernDisp0GenPipe genpipe[APPLE_MODERN_DISP0_GP_COUNT];
    uint64_t reads, writes, faults, kicks;
    uint32_t frontier_count;
    AppleModernDisp0Frontier frontier[APPLE_MODERN_DISP0_FRONTIER_SLOTS];
} AppleModernDisp0Core;

/*
 * Derive the window plan from the served ADT, which is never modified. Every
 * window is translated through /arm-io ranges and must match exactly once;
 * the pipe aperture must decompose as k * shadow stride + block span; windows
 * that contain /arm-io/dcp's registers, or that lie inside an /arm-io/pmgr
 * reg window, are classified and left unmapped because another node owns
 * them. Mapped windows must lie outside DRAM and outside every exclusion.
 * Output must not alias the inputs. Any failure refuses the plan.
 */
bool apple_modern_disp0_plan_build(AppleModernBlob dtree, uint64_t dram_base,
    uint64_t dram_size, const AppleModernAddressRange *exclusions,
    size_t exclusion_count, AppleModernDisp0Plan *output, Error **errp);

void apple_modern_disp0_core_reset(AppleModernDisp0Core *core);

/*
 * Decode one access. Both return false for every offset this model does not
 * represent, which the MMIO wrapper turns into MEMTX_ACCESS_ERROR so the
 * guest takes an external abort; the access is recorded in the frontier
 * table either way. *kick is set when a write asked the pipe to compose.
 */
bool apple_modern_disp0_core_read(AppleModernDisp0Core *core, unsigned window,
    uint64_t offset, unsigned size, uint32_t *value);
bool apple_modern_disp0_core_write(AppleModernDisp0Core *core, unsigned window,
    uint64_t offset, unsigned size, uint32_t value, bool *kick);

/* Raise/lower the modelled interrupt-status bits; returns the new IRQ level. */
bool apple_modern_disp0_core_raise(AppleModernDisp0Core *core, uint32_t bits);
bool apple_modern_disp0_core_irq_level(const AppleModernDisp0Core *core);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#include "chardev/char.h"
#define TYPE_APPLE_MODERN_DISP0 "apple-modern-disp0"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernDisp0State, APPLE_MODERN_DISP0)
DeviceState *apple_modern_disp0_new(const AppleModernDisp0Plan *plan,
                                    MemoryRegion *ram, uint64_t framebuffer_offset,
                                    uint32_t width, uint32_t height,
                                    uint32_t stride, Chardev *uart);
#endif
#endif
