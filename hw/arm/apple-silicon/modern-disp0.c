/*
 * T8140 /arm-io/disp0 unified display pipe — declared, default-off skeleton.
 *
 * Copyright (c) 2023-2026 Visual Ehrmanntraut (VisualEhrmanntraut).
 * Copyright (c) 2023-2026 Christian Inci (chris-pcguy).
 * Copyright (c) 2026 the Inferno-and-Darwin-VM project.
 *
 * Derived from the A13/t8030 model hw/display/apple_displaypipe_v4.c in this
 * same repository, by the authors named above, under AGPL-3.0-or-later. What
 * is reused: the control/GenPipe/Blend register taxonomy and offsets, the
 * frame-size encoding, the dirty-region console scanout, and above all the
 * self-driven scanout timer whose comment in that file records why a display
 * pipe that only updates from a UI backend wedges a headless guest in
 * IOMobileFramebufferLegacy::swap_wait_gated. What is new: the T8140 six-window
 * plan derived from the served ADT, the shadow-stride generalisation, a decode
 * that FAULTS on every offset it does not represent (so the next real guest
 * requirement appears as a frontier record instead of a silent zero), and the
 * gates.
 *
 * Nothing here is attested for T8140 beyond the window geometry, the interrupt
 * count and the dot pitch, all of which come from the stock ADT. Every register
 * offset is ANALOGY from t8030. See the evidence README for the labels.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "system/dma.h"
#include "system/address-spaces.h"
#include "ui/console.h"
#endif
#include "hw/arm/apple-silicon/modern-disp0.h"
#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/arm/apple-silicon/modern-boot-input.h"
#endif

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
static void error_setg(Error **errp, const char *format, ...)
{
    if (errp) {
        va_list args;
        if (*errp) {
            abort();
        }
        *errp = calloc(1, sizeof(**errp));
        if (!*errp) {
            abort();
        }
        va_start(args, format);
        vsnprintf((*errp)->message, sizeof((*errp)->message), format, args);
        va_end(args);
    }
}
#endif

static uint64_t little(const uint8_t *p, unsigned size)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < size; i++) {
        value |= (uint64_t)p[i] << (8 * i);
    }
    return value;
}

static bool aliases(const void *a, size_t as, const void *b, size_t bs)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return as && bs && (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y ||
                        (x < y + bs && y < x + as));
}

static bool overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    return as && bs && a < b + bs && b < a + as;
}

/* Translate one /arm-io child window through the node's ranges. Exactly one
 * range must contain it, as everywhere else in this board. */
static bool translate(AppleModernBlob ranges, uint64_t child, uint64_t size,
                      uint64_t *physical, Error **errp)
{
    unsigned matches = 0;

    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t c = little(ranges.data + i, 8);
        uint64_t p = little(ranges.data + i + 8, 8);
        uint64_t n = little(ranges.data + i + 16, 8);

        if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
            error_setg(errp, "disp0: /arm-io bus range is empty or wraps");
            return false;
        }
        if (child >= c && child - c <= n && size <= n - (child - c)) {
            *physical = p + (child - c);
            matches++;
        }
    }
    if (matches != 1) {
        error_setg(errp, "disp0: window 0x%llx is unmapped or ambiguous",
                   (unsigned long long)child);
        return false;
    }
    return true;
}

/* Does [address, size) lie inside any reg window of the named /arm-io node?
 * Absent nodes and absent reg properties simply answer no. */
static bool inside_node(AppleModernBlob dtree, AppleModernBlob ranges,
                        const char *path, uint64_t address, uint64_t size,
                        bool *result, Error **errp)
{
    AppleModernBlob reg;

    *result = false;
    if (!apple_modern_adt_property(dtree, path, "reg", &reg, NULL)) {
        return true;
    }
    if (!reg.size || reg.size % 16) {
        error_setg(errp, "disp0: %s has invalid reg geometry", path);
        return false;
    }
    for (size_t i = 0; i < reg.size; i += 16) {
        uint64_t other, span = little(reg.data + i + 8, 8);
        if (!span || !translate(ranges, little(reg.data + i, 8), span, &other,
                                errp)) {
            if (!span) {
                error_setg(errp, "disp0: %s reg window is empty", path);
            }
            return false;
        }
        if (address >= other && address - other <= span - 1 &&
            size <= span - (address - other)) {
            *result = true;
            return true;
        }
    }
    return true;
}

/* Does [address, size) contain any reg window of the named /arm-io node? */
static bool contains_node(AppleModernBlob dtree, AppleModernBlob ranges,
                          const char *path, uint64_t address, uint64_t size,
                          bool *result, Error **errp)
{
    AppleModernBlob reg;

    *result = false;
    if (!apple_modern_adt_property(dtree, path, "reg", &reg, NULL)) {
        return true;
    }
    if (!reg.size || reg.size % 16) {
        error_setg(errp, "disp0: %s has invalid reg geometry", path);
        return false;
    }
    for (size_t i = 0; i < reg.size; i += 16) {
        uint64_t other, span = little(reg.data + i + 8, 8);
        if (!span) {
            error_setg(errp, "disp0: %s reg window is empty", path);
            return false;
        }
        if (!translate(ranges, little(reg.data + i, 8), span, &other, errp)) {
            return false;
        }
        if (other >= address && other - address <= size - 1 &&
            span <= size - (other - address)) {
            *result = true;
            return true;
        }
    }
    return true;
}

/*
 * The attested iPhone17,3 / d47ap /arm-io/disp0 schema, read out of the stock
 * ADT (dtree.stock) and still present in the served Darwin tree: six child
 * windows, nine interrupts and a 460 ppi dot pitch. These are a cross-check,
 * not the source: the addresses the plan uses are translated out of the tree
 * through /arm-io ranges. A tree that disagrees is refused rather than
 * modelled, so this option can never attach to a node it does not know.
 */
static const uint64_t kDisp0Child[APPLE_MODERN_DISP0_WINDOWS][2] = {
    { UINT64_C(0x200000000), 0xafc000 }, { UINT64_C(0x202240000), 0x10000 },
    { UINT64_C(0x2023a8000), 0x4000 },   { UINT64_C(0x2023ac000), 0x4000 },
    { UINT64_C(0x202800000), 0x800000 }, { UINT64_C(0xf2800000), 0xbc000 },
};
static const uint32_t kDisp0Irq[APPLE_MODERN_DISP0_IRQS] = {
    0x2b1, 0x2c4, 0x2b4, 0x2b3, 0x2b2, 0x2b9, 0x2af, 0x2bd, 0x2b8,
};
#define APPLE_MODERN_DISP0_DOT_PITCH 460

bool apple_modern_disp0_plan_build(AppleModernBlob dtree, uint64_t dram_base,
    uint64_t dram_size, const AppleModernAddressRange *exclusions,
    size_t exclusion_count, AppleModernDisp0Plan *output, Error **errp)
{
    AppleModernBlob compatible, device_type, reg, interrupts, ranges, pitch;
    AppleModernDisp0Plan plan;
    static const char kCompatible[] = "disp0,t8140";
    static const char kDeviceType[] = "display-subsystem";

    memset(&plan, 0, sizeof(plan));
    if (!output || aliases(output, sizeof(*output), dtree.data, dtree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "disp0: output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "disp0: DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size ||
            exclusions[i].size > UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "disp0: exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/disp0", "device_type",
                                   &device_type, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/disp0", "reg", &reg, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/disp0", "interrupts",
                                   &interrupts, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/disp0", "dot-pitch", &pitch,
                                   errp) ||
        !apple_modern_adt_property(dtree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    /*
     * The served Darwin tree strips `compatible` from every /arm-io node, so
     * an absent value is normal and accepted; a value that is present must be
     * exactly this part's. device_type, which dt_fixup does not strip, plus
     * the window/interrupt/dot-pitch schema below are the anchors.
     */
    if (apple_modern_adt_property(dtree, "/arm-io/disp0", "compatible",
                                  &compatible, NULL) &&
        (compatible.size != sizeof(kCompatible) ||
         memcmp(compatible.data, kCompatible, sizeof(kCompatible)))) {
        error_setg(errp, "disp0: compatible is present but is not \"%s\"",
                   kCompatible);
        return false;
    }
    if (device_type.size != sizeof(kDeviceType) ||
        memcmp(device_type.data, kDeviceType, sizeof(kDeviceType))) {
        error_setg(errp, "disp0: device_type is not \"%s\"", kDeviceType);
        return false;
    }
    if (reg.size != APPLE_MODERN_DISP0_WINDOWS * 16 ||
        interrupts.size != APPLE_MODERN_DISP0_IRQS * 4 || pitch.size != 4 ||
        !ranges.size || ranges.size % 24) {
        error_setg(errp, "disp0: needs the matched T8140 schema "
                   "(6 reg windows, 9 interrupts, a dot pitch)");
        return false;
    }
    plan.dot_pitch = (uint32_t)little(pitch.data, 4);
    if (plan.dot_pitch != APPLE_MODERN_DISP0_DOT_PITCH) {
        error_setg(errp, "disp0: dot-pitch %u is not the attested %u",
                   plan.dot_pitch, APPLE_MODERN_DISP0_DOT_PITCH);
        return false;
    }
    for (unsigned i = 0; i < APPLE_MODERN_DISP0_IRQS; i++) {
        plan.interrupts[i] = (uint32_t)little(interrupts.data + i * 4, 4);
        if (plan.interrupts[i] != kDisp0Irq[i]) {
            error_setg(errp, "disp0: interrupt %u is 0x%x, not the attested "
                       "0x%x", i, plan.interrupts[i], kDisp0Irq[i]);
            return false;
        }
    }
    for (unsigned i = 0; i < APPLE_MODERN_DISP0_WINDOWS; i++) {
        uint64_t child = little(reg.data + i * 16, 8);
        uint64_t size = little(reg.data + i * 16 + 8, 8);
        uint64_t address;
        bool holds_dcp = false, in_pmgr = false;

        if (!size || size > (UINT64_C(16) << 20) || (size & 0xfff)) {
            error_setg(errp, "disp0: window %u has an implausible size", i);
            return false;
        }
        if (child != kDisp0Child[i][0] || size != kDisp0Child[i][1]) {
            error_setg(errp, "disp0: window %u is 0x%llx/0x%llx, not the "
                       "attested 0x%llx/0x%llx", i,
                       (unsigned long long)child, (unsigned long long)size,
                       (unsigned long long)kDisp0Child[i][0],
                       (unsigned long long)kDisp0Child[i][1]);
            return false;
        }
        if (!translate(ranges, child, size, &address, errp)) {
            return false;
        }
        if (address & 0xfff) {
            error_setg(errp, "disp0: window %u is not page aligned", i);
            return false;
        }
        plan.windows[i].address = address;
        plan.windows[i].size = size;
        if (i == 0) {
            /*
             * The pipe aperture. Both attested sizes decompose as
             * k * 0x200000 + 0xfc000; anything else means the block map moved
             * and the ANALOGY offsets below must not be applied blind.
             */
            if (size <= APPLE_MODERN_DISP0_BLOCK_SPAN ||
                (size - APPLE_MODERN_DISP0_BLOCK_SPAN) %
                    APPLE_MODERN_DISP0_SHADOW_STRIDE) {
                error_setg(errp, "disp0: pipe aperture 0x%llx does not "
                           "decompose as k * 0x%x + 0x%x",
                           (unsigned long long)size,
                           APPLE_MODERN_DISP0_SHADOW_STRIDE,
                           APPLE_MODERN_DISP0_BLOCK_SPAN);
                return false;
            }
            plan.shadow_copies = (uint32_t)((size -
                APPLE_MODERN_DISP0_BLOCK_SPAN) /
                APPLE_MODERN_DISP0_SHADOW_STRIDE);
            plan.windows[i].kind = APPLE_MODERN_DISP0_WINDOW_PIPE;
        } else {
            if (!contains_node(dtree, ranges, "/arm-io/dcp", address, size,
                               &holds_dcp, errp) ||
                !inside_node(dtree, ranges, "/arm-io/pmgr", address, size,
                             &in_pmgr, errp)) {
                return false;
            }
            plan.windows[i].kind = holds_dcp
                ? APPLE_MODERN_DISP0_WINDOW_DCP
                : (in_pmgr ? APPLE_MODERN_DISP0_WINDOW_PMGR
                           : APPLE_MODERN_DISP0_WINDOW_OPAQUE);
        }
        plan.windows[i].mapped =
            plan.windows[i].kind == APPLE_MODERN_DISP0_WINDOW_PIPE ||
            plan.windows[i].kind == APPLE_MODERN_DISP0_WINDOW_OPAQUE;
    }
    for (unsigned i = 0; i < APPLE_MODERN_DISP0_WINDOWS; i++) {
        if (!plan.windows[i].mapped) {
            continue;
        }
        plan.mapped_count++;
        if (overlaps(plan.windows[i].address, plan.windows[i].size, dram_base,
                     dram_size)) {
            error_setg(errp, "disp0: window %u overlaps DRAM", i);
            return false;
        }
        for (size_t j = 0; j < exclusion_count; j++) {
            if (overlaps(plan.windows[i].address, plan.windows[i].size,
                         exclusions[j].physical_address, exclusions[j].size)) {
                error_setg(errp, "disp0: window %u overlaps another device", i);
                return false;
            }
        }
        for (unsigned j = 0; j < i; j++) {
            if (plan.windows[j].mapped &&
                overlaps(plan.windows[i].address, plan.windows[i].size,
                         plan.windows[j].address, plan.windows[j].size)) {
                error_setg(errp, "disp0: windows %u and %u overlap", j, i);
                return false;
            }
        }
    }
    if (!plan.mapped_count) {
        error_setg(errp, "disp0: no window is ours to map");
        return false;
    }
    *output = plan;
    return true;
}

void apple_modern_disp0_core_reset(AppleModernDisp0Core *core)
{
    AppleModernDisp0Plan plan = core->plan;
    uint32_t width = core->width, height = core->height;
    uint32_t version = core->version;

    memset(core, 0, sizeof(*core));
    core->plan = plan;
    core->width = width;
    core->height = height;
    core->version = version;
}

static void record(AppleModernDisp0Core *core, unsigned window, uint64_t offset,
                   unsigned size, bool is_write)
{
    uint64_t base = window < APPLE_MODERN_DISP0_WINDOWS
                        ? core->plan.windows[window].address : 0;

    if (core->faults != UINT64_MAX) {
        core->faults++;
    }
    for (uint32_t i = 0; i < core->frontier_count; i++) {
        if (core->frontier[i].window == window &&
            core->frontier[i].offset == (uint32_t)offset &&
            core->frontier[i].is_write == is_write) {
            return;
        }
    }
    if (core->frontier_count >= APPLE_MODERN_DISP0_FRONTIER_SLOTS) {
        return;
    }
    core->frontier[core->frontier_count++] = (AppleModernDisp0Frontier){
        .address = base + offset, .offset = (uint32_t)offset,
        .window = (uint8_t)window, .size = (uint8_t)size,
        .is_write = is_write, .valid = 1,
    };
}

/* Fold the pipe aperture's shadow aliases onto the block map, as the t8030
 * model does with its single `if (addr >= 0x200000) addr -= 0x200000`. */
static bool fold(const AppleModernDisp0Core *core, uint64_t offset,
                 uint64_t *folded)
{
    if (offset >= (uint64_t)core->plan.shadow_copies *
                      APPLE_MODERN_DISP0_SHADOW_STRIDE +
                      APPLE_MODERN_DISP0_BLOCK_SPAN) {
        return false;
    }
    *folded = offset % APPLE_MODERN_DISP0_SHADOW_STRIDE;
    return *folded < APPLE_MODERN_DISP0_BLOCK_SPAN;
}

static bool genpipe_index(uint64_t offset, unsigned *index, uint64_t *local)
{
    if (offset < APPLE_MODERN_DISP0_GP_BASE) {
        return false;
    }
    uint64_t rel = offset - APPLE_MODERN_DISP0_GP_BASE;
    if (rel >= (uint64_t)APPLE_MODERN_DISP0_GP_COUNT *
                   APPLE_MODERN_DISP0_GP_BLOCK_STRIDE) {
        return false;
    }
    *index = (unsigned)(rel / APPLE_MODERN_DISP0_GP_BLOCK_STRIDE);
    *local = rel % APPLE_MODERN_DISP0_GP_BLOCK_STRIDE;
    return true;
}

static bool genpipe_read(const AppleModernDisp0GenPipe *gp, uint64_t local,
                         uint32_t *value)
{
    switch (local) {
    case APPLE_MODERN_DISP0_GP_CONFIG:
        *value = gp->config;
        return true;
    case APPLE_MODERN_DISP0_GP_PIXFMT:
        *value = gp->pixel_format;
        return true;
    case APPLE_MODERN_DISP0_GP_DATA_START:
        *value = gp->data_start;
        return true;
    case APPLE_MODERN_DISP0_GP_DATA_END:
        *value = gp->data_end;
        return true;
    case APPLE_MODERN_DISP0_GP_STRIDE:
        *value = gp->stride;
        return true;
    case APPLE_MODERN_DISP0_GP_SRC_DIMS:
        *value = ((uint32_t)gp->src_width << 16) | gp->src_height;
        return true;
    case APPLE_MODERN_DISP0_GP_DEST_DIMS:
        *value = ((uint32_t)gp->dest_width << 16) | gp->dest_height;
        return true;
    default:
        return false;
    }
}

static bool genpipe_write(AppleModernDisp0GenPipe *gp, uint64_t local,
                          uint32_t value)
{
    switch (local) {
    case APPLE_MODERN_DISP0_GP_CONFIG:
        gp->config = value;
        return true;
    case APPLE_MODERN_DISP0_GP_PIXFMT:
        gp->pixel_format = value;
        return true;
    case APPLE_MODERN_DISP0_GP_DATA_START:
        gp->data_start = value;
        return true;
    case APPLE_MODERN_DISP0_GP_DATA_END:
        gp->data_end = value;
        return true;
    case APPLE_MODERN_DISP0_GP_STRIDE:
        gp->stride = value;
        return true;
    case APPLE_MODERN_DISP0_GP_SRC_DIMS:
        gp->src_height = value & 0xffff;
        gp->src_width = (value >> 16) & 0xffff;
        return true;
    case APPLE_MODERN_DISP0_GP_DEST_DIMS:
        gp->dest_height = value & 0xffff;
        gp->dest_width = (value >> 16) & 0xffff;
        return true;
    default:
        return false;
    }
}

bool apple_modern_disp0_core_read(AppleModernDisp0Core *core, unsigned window,
    uint64_t offset, unsigned size, uint32_t *value)
{
    uint64_t folded, local;
    unsigned index;

    if (!core || !value || size != 4 || (offset & 3) ||
        window >= APPLE_MODERN_DISP0_WINDOWS ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    if (!core->plan.windows[window].mapped ||
        offset > core->plan.windows[window].size - 4) {
        record(core, window, offset, size, false);
        return false;
    }
    if (core->plan.windows[window].kind != APPLE_MODERN_DISP0_WINDOW_PIPE ||
        !fold(core, offset, &folded)) {
        record(core, window, offset, size, false);
        return false;
    }
    if (folded >= APPLE_MODERN_DISP0_BLEND_BASE &&
        folded < APPLE_MODERN_DISP0_BLEND_BASE +
                     APPLE_MODERN_DISP0_BLEND_SPAN) {
        switch (folded - APPLE_MODERN_DISP0_BLEND_BASE) {
        case APPLE_MODERN_DISP0_BLEND_LAYER0:
            *value = core->blend_layer[0];
            break;
        case APPLE_MODERN_DISP0_BLEND_LAYER1:
            *value = core->blend_layer[1];
            break;
        default:
            record(core, window, folded, size, false);
            return false;
        }
    } else if (genpipe_index(folded, &index, &local)) {
        if (!genpipe_read(&core->genpipe[index], local, value)) {
            record(core, window, folded, size, false);
            return false;
        }
    } else {
        switch (folded) {
        case APPLE_MODERN_DISP0_INT_STATUS:
            *value = core->int_status;
            break;
        case APPLE_MODERN_DISP0_INT_ENABLE:
            *value = core->int_enable;
            break;
        case APPLE_MODERN_DISP0_VERSION:
            *value = core->version;
            break;
        case APPLE_MODERN_DISP0_FRAME_SIZE:
            *value = (core->width << 16) | core->height;
            break;
        default:
            record(core, window, folded, size, false);
            return false;
        }
    }
    if (core->reads != UINT64_MAX) {
        core->reads++;
    }
    return true;
}

bool apple_modern_disp0_core_write(AppleModernDisp0Core *core, unsigned window,
    uint64_t offset, unsigned size, uint32_t value, bool *kick)
{
    uint64_t folded, local;
    unsigned index;

    if (kick) {
        *kick = false;
    }
    if (!core || size != 4 || (offset & 3) ||
        window >= APPLE_MODERN_DISP0_WINDOWS) {
        return false;
    }
    if (!core->plan.windows[window].mapped ||
        offset > core->plan.windows[window].size - 4) {
        record(core, window, offset, size, true);
        return false;
    }
    if (core->plan.windows[window].kind != APPLE_MODERN_DISP0_WINDOW_PIPE ||
        !fold(core, offset, &folded)) {
        record(core, window, offset, size, true);
        return false;
    }
    if (folded >= APPLE_MODERN_DISP0_BLEND_BASE &&
        folded < APPLE_MODERN_DISP0_BLEND_BASE +
                     APPLE_MODERN_DISP0_BLEND_SPAN) {
        switch (folded - APPLE_MODERN_DISP0_BLEND_BASE) {
        case APPLE_MODERN_DISP0_BLEND_LAYER0:
            core->blend_layer[0] = value;
            break;
        case APPLE_MODERN_DISP0_BLEND_LAYER1:
            core->blend_layer[1] = value;
            break;
        default:
            record(core, window, folded, size, true);
            return false;
        }
    } else if (genpipe_index(folded, &index, &local)) {
        if (!genpipe_write(&core->genpipe[index], local, value)) {
            record(core, window, folded, size, true);
            return false;
        }
    } else {
        switch (folded) {
        case APPLE_MODERN_DISP0_INT_STATUS:
            /* Write-one-to-clear, as on t8030. */
            core->int_status &= ~value;
            break;
        case APPLE_MODERN_DISP0_INT_ENABLE:
            core->int_enable = value;
            break;
        case APPLE_MODERN_DISP0_KICK:
            if (value & (1u << APPLE_MODERN_DISP0_KICK_BIT)) {
                if (core->kicks != UINT64_MAX) {
                    core->kicks++;
                }
                if (kick) {
                    *kick = true;
                }
            }
            break;
        default:
            record(core, window, folded, size, true);
            return false;
        }
    }
    if (core->writes != UINT64_MAX) {
        core->writes++;
    }
    return true;
}

bool apple_modern_disp0_core_raise(AppleModernDisp0Core *core, uint32_t bits)
{
    if (!core) {
        return false;
    }
    core->int_status |= bits;
    return apple_modern_disp0_core_irq_level(core);
}

bool apple_modern_disp0_core_irq_level(const AppleModernDisp0Core *core)
{
    return core && (core->int_status & core->int_enable) != 0;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
/* ---------------------------------------------------------------------------
 * QEMU half. The scanout, dirty tracking and the 60 Hz self-driven timer are
 * the t8030 model's, kept deliberately close to it so its measured lesson
 * carries over: without the timer no backend calls gfx_update under
 * -display none, OUTPUT_READY is never raised and an IOMFB client blocks in
 * swap_wait_gated forever.
 * ------------------------------------------------------------------------ */
#define APPLE_MODERN_DISP0_SCANOUT_NS (NANOSECONDS_PER_SECOND / 60)

typedef struct Disp0View {
    struct AppleModernDisp0State *owner;
    unsigned index;
} Disp0View;

struct AppleModernDisp0State {
    SysBusDevice parent_obj;
    AppleModernDisp0Core core;
    Disp0View views[APPLE_MODERN_DISP0_WINDOWS];
    MemoryRegion iomem[APPLE_MODERN_DISP0_WINDOWS];
    qemu_irq irqs[APPLE_MODERN_DISP0_IRQS];
    MemoryRegion *ram;
    uint64_t framebuffer_offset;
    uint32_t width, height, stride;
    QemuConsole *console;
    QEMUTimer *scanout;
    QEMUBH *compose;
    Chardev *uart;
    AppleModernConsoleInput *input;
    uint64_t announced[APPLE_MODERN_DISP0_WINDOWS];
};

static void disp0_update_irq(AppleModernDisp0State *s)
{
    qemu_set_irq(s->irqs[0], apple_modern_disp0_core_irq_level(&s->core));
}

/* One line per distinct rejected register, once, so a run shows exactly which
 * requirement the guest hit first. */
static void announce(AppleModernDisp0State *s, unsigned window, uint64_t offset,
                     unsigned size, bool is_write)
{
    uint64_t slot = offset >> 12;

    if (slot < 64 && ((s->announced[window] >> slot) & 1)) {
        return;
    }
    if (slot < 64) {
        s->announced[window] |= UINT64_C(1) << slot;
    }
    info_report("apple-modern disp0: REJECTED %s of window %u +0x%" PRIx64
                " (%u bytes, address 0x%" PRIx64 ")",
                is_write ? "write" : "read", window, offset, size,
                s->core.plan.windows[window].address + offset);
}

static MemTxResult disp0_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    Disp0View *view = opaque;
    AppleModernDisp0State *s = view->owner;
    uint32_t word = 0;

    if (!apple_modern_disp0_core_read(&s->core, view->index, offset, size,
                                      &word)) {
        announce(s, view->index, offset, size, false);
        return MEMTX_ACCESS_ERROR;
    }
    *value = word;
    return MEMTX_OK;
}

static MemTxResult disp0_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    Disp0View *view = opaque;
    AppleModernDisp0State *s = view->owner;
    bool kick = false;

    if (size != 4 || !apple_modern_disp0_core_write(&s->core, view->index,
            offset, size, (uint32_t)value, &kick)) {
        announce(s, view->index, offset, size, true);
        return MEMTX_ACCESS_ERROR;
    }
    if (kick) {
        qemu_bh_schedule(s->compose);
    }
    disp0_update_irq(s);
    return MEMTX_OK;
}

static const MemoryRegionOps disp0_ops = {
    .read_with_attrs = disp0_read,
    .write_with_attrs = disp0_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .unaligned = false },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static uint8_t *disp0_framebuffer(AppleModernDisp0State *s)
{
    return (uint8_t *)memory_region_get_ram_ptr(s->ram) +
           s->framebuffer_offset;
}

/* t8030's adp_v4_gfx_update, with the same per-line dirty runs. */
static void disp0_gfx_update(void *opaque)
{
    AppleModernDisp0State *s = opaque;
    DirtyBitmapSnapshot *snap;
    uint32_t y, ys = -1U;
    uint64_t span = (uint64_t)s->stride * s->height;

    snap = memory_region_snapshot_and_clear_dirty(s->ram,
        s->framebuffer_offset, span, DIRTY_MEMORY_VGA);
    for (y = 0; y < s->height; y++) {
        bool dirty = memory_region_snapshot_get_dirty(s->ram, snap,
            s->framebuffer_offset + (uint64_t)s->stride * y, s->stride);
        if (dirty && ys == -1U) {
            ys = y;
        }
        if (!dirty && ys != -1U) {
            dpy_gfx_update(s->console, 0, ys, s->width, y - ys);
            ys = -1U;
        }
    }
    if (ys != -1U) {
        dpy_gfx_update(s->console, 0, ys, s->width, y - ys);
    }
    g_free(snap);

    apple_modern_disp0_core_raise(&s->core,
                                  APPLE_MODERN_DISP0_INT_OUTPUT_READY);
    disp0_update_irq(s);
}

static void disp0_invalidate(void *opaque)
{
    AppleModernDisp0State *s = opaque;

    memory_region_set_dirty(s->ram, s->framebuffer_offset,
                            (uint64_t)s->stride * s->height);
}

static const GraphicHwOps disp0_gfx_ops = {
    .invalidate = disp0_invalidate,
    .gfx_update = disp0_gfx_update,
};

static void disp0_scanout_tick(void *opaque)
{
    AppleModernDisp0State *s = opaque;

    graphic_hw_update(s->console);
    timer_mod(s->scanout, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                              APPLE_MODERN_DISP0_SCANOUT_NS);
}

/*
 * Composition, after a kick. Each running GenPipe's layer-0 buffer is read
 * from the system address space and blitted over the framebuffer. DECLARED:
 * no DART translation is modelled, so a device virtual address only lands if
 * it equals its physical address; compressed surfaces are dropped exactly as
 * the t8030 model drops them, because no public decoder exists.
 */
static void disp0_compose(void *opaque)
{
    AppleModernDisp0State *s = opaque;
    uint8_t *dest = disp0_framebuffer(s);

    for (unsigned i = 0; i < APPLE_MODERN_DISP0_GP_COUNT; i++) {
        AppleModernDisp0GenPipe *gp = &s->core.genpipe[i];
        uint32_t rows, row_bytes;

        if (!(gp->config & APPLE_MODERN_DISP0_GP_CONFIG_RUN) ||
            !(gp->config & APPLE_MODERN_DISP0_GP_CONFIG_ENABLED)) {
            continue;
        }
        if (gp->pixel_format & APPLE_MODERN_DISP0_GP_PIXFMT_COMPRESSED) {
            qemu_log_mask(LOG_GUEST_ERROR, "apple-modern disp0: gp%u frame "
                          "dropped, compressed surfaces are not decoded\n", i);
            continue;
        }
        if (!gp->src_width || !gp->src_height || !gp->stride) {
            continue;
        }
        rows = gp->src_height < s->height ? gp->src_height : s->height;
        row_bytes = (uint32_t)gp->src_width * 4;
        if (row_bytes > s->stride) {
            row_bytes = s->stride;
        }
        if (row_bytes > gp->stride) {
            row_bytes = gp->stride;
        }
        for (uint32_t y = 0; y < rows; y++) {
            if (dma_memory_read(&address_space_memory,
                                (uint64_t)gp->data_start +
                                    (uint64_t)gp->stride * y,
                                dest + (uint64_t)s->stride * y, row_bytes,
                                MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
                qemu_log_mask(LOG_GUEST_ERROR, "apple-modern disp0: gp%u DMA "
                              "read failed at row %u\n", i, y);
                break;
            }
        }
        memory_region_set_dirty(s->ram, s->framebuffer_offset,
                                (uint64_t)s->stride * rows);
    }
    apple_modern_disp0_core_raise(&s->core,
                                  APPLE_MODERN_DISP0_INT_FRAME_PROCESSED);
    disp0_update_irq(s);
}

static void disp0_reset(DeviceState *dev)
{
    AppleModernDisp0State *s = APPLE_MODERN_DISP0(dev);

    apple_modern_disp0_core_reset(&s->core);
    memset(s->announced, 0, sizeof(s->announced));
    apple_modern_console_input_reset(s->input);
    disp0_update_irq(s);
}

static void disp0_realize(DeviceState *dev, Error **errp)
{
    AppleModernDisp0State *s = APPLE_MODERN_DISP0(dev);
    uint64_t span;

    if (!s->ram || !memory_region_is_ram(s->ram) || !s->width || !s->height ||
        s->width > 4096 || s->height > 4096 ||
        s->stride < (uint64_t)s->width * 4 || (s->stride & 3)) {
        error_setg(errp, "apple-modern disp0 needs bounded 32-bit geometry");
        return;
    }
    span = (uint64_t)s->stride * s->height;
    if (span > 64 * MiB || s->framebuffer_offset > memory_region_size(s->ram) ||
        span > memory_region_size(s->ram) - s->framebuffer_offset) {
        error_setg(errp, "apple-modern disp0 framebuffer leaves its RAM "
                   "reservation");
        return;
    }
    s->core.width = s->width;
    s->core.height = s->height;
    apple_modern_disp0_core_reset(&s->core);
    for (unsigned i = 0; i < APPLE_MODERN_DISP0_WINDOWS; i++) {
        if (!s->core.plan.windows[i].mapped) {
            continue;
        }
        s->views[i] = (Disp0View){ s, i };
        memory_region_init_io(&s->iomem[i], OBJECT(dev), &disp0_ops,
                              &s->views[i], "apple-modern.disp0",
                              s->core.plan.windows[i].size);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->iomem[i]);
    }
    for (unsigned i = 0; i < APPLE_MODERN_DISP0_IRQS; i++) {
        sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irqs[i]);
    }
    s->compose = qemu_bh_new_guarded(disp0_compose, s, &dev->mem_reentrancy_guard);
    s->console = graphic_console_init(dev, 0, &disp0_gfx_ops, s);
    dpy_gfx_replace_surface(s->console, qemu_create_displaysurface_from(
        s->width, s->height, PIXMAN_x8r8g8b8, s->stride, disp0_framebuffer(s)));
    s->input = apple_modern_console_input_create(dev, s->console, s->uart);
    if (s->uart && !s->input) {
        graphic_console_close(s->console);
        s->console = NULL;
        error_setg(errp, "cannot bind the disp0 console keyboard");
        return;
    }
    s->scanout = timer_new_ns(QEMU_CLOCK_VIRTUAL, disp0_scanout_tick, s);
    timer_mod(s->scanout, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                              APPLE_MODERN_DISP0_SCANOUT_NS);
}

static void disp0_unrealize(DeviceState *dev)
{
    AppleModernDisp0State *s = APPLE_MODERN_DISP0(dev);

    if (s->scanout) {
        timer_free(s->scanout);
        s->scanout = NULL;
    }
    if (s->compose) {
        qemu_bh_delete(s->compose);
        s->compose = NULL;
    }
    apple_modern_console_input_destroy(s->input);
    s->input = NULL;
    if (s->console) {
        graphic_console_close(s->console);
        s->console = NULL;
    }
}

static void disp0_get_counter(Object *obj, Visitor *v, const char *name,
                              void *opaque, Error **errp)
{
    AppleModernDisp0State *s = APPLE_MODERN_DISP0(obj);
    uint64_t value = *(uint64_t *)((uint8_t *)&s->core + (uintptr_t)opaque);

    visit_type_uint64(v, name, &value, errp);
}

static char *disp0_get_frontier(Object *obj, Error **errp)
{
    AppleModernDisp0State *s = APPLE_MODERN_DISP0(obj);
    GString *out = g_string_new(NULL);

    for (uint32_t i = 0; i < s->core.frontier_count; i++) {
        AppleModernDisp0Frontier *f = &s->core.frontier[i];
        g_string_append_printf(out, "%s%u:0x%" PRIx64 ":0x%x:%s",
                               i ? "," : "", f->window, f->address, f->offset,
                               f->is_write ? "w" : "r");
    }
    return g_string_free(out, FALSE);
}

static char *disp0_get_window_map(Object *obj, Error **errp)
{
    AppleModernDisp0State *s = APPLE_MODERN_DISP0(obj);
    static const char *const kinds[] = { "pipe", "opaque", "dcp", "pmgr" };
    GString *out = g_string_new(NULL);

    for (unsigned i = 0; i < APPLE_MODERN_DISP0_WINDOWS; i++) {
        AppleModernDisp0Window *w = &s->core.plan.windows[i];
        g_string_append_printf(out, "%s%u:0x%" PRIx64 ":0x%" PRIx64 ":%s:%s",
                               i ? "," : "", i, w->address, w->size,
                               kinds[w->kind < 4 ? w->kind : 1],
                               w->mapped ? "mapped" : "skipped");
    }
    return g_string_free(out, FALSE);
}

static const Property disp0_properties[] = {
    DEFINE_PROP_LINK("ram", AppleModernDisp0State, ram, TYPE_MEMORY_REGION,
                     MemoryRegion *),
    DEFINE_PROP_UINT64("framebuffer-offset", AppleModernDisp0State,
                       framebuffer_offset, 0),
    DEFINE_PROP_UINT32("width", AppleModernDisp0State, width, 0),
    DEFINE_PROP_UINT32("height", AppleModernDisp0State, height, 0),
    DEFINE_PROP_UINT32("stride", AppleModernDisp0State, stride, 0),
    DEFINE_PROP_LINK("uart", AppleModernDisp0State, uart, TYPE_CHARDEV,
                     Chardev *),
};

static const VMStateDescription disp0_unmigratable = {
    .name = TYPE_APPLE_MODERN_DISP0, .unmigratable = 1,
};

static void disp0_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = disp0_realize;
    dc->unrealize = disp0_unrealize;
    dc->vmsd = &disp0_unmigratable;
    dc->user_creatable = false;
    dc->desc = "Apple T8140 disp0 unified display pipe (declared skeleton)";
    device_class_set_legacy_reset(dc, disp0_reset);
    device_class_set_props(dc, disp0_properties);
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    object_class_property_add(oc, "mmio-read-count", "uint64",
        disp0_get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDisp0Core, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64",
        disp0_get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDisp0Core, writes));
    object_class_property_add(oc, "mmio-fault-count", "uint64",
        disp0_get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDisp0Core, faults));
    object_class_property_add(oc, "kick-count", "uint64", disp0_get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDisp0Core, kicks));
    object_class_property_add_str(oc, "frontier", disp0_get_frontier, NULL);
    object_class_property_add_str(oc, "window-map", disp0_get_window_map, NULL);
}

static const TypeInfo disp0_type = {
    .name = TYPE_APPLE_MODERN_DISP0,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernDisp0State),
    .class_init = disp0_class_init,
};

static void disp0_register_types(void)
{
    type_register_static(&disp0_type);
}
type_init(disp0_register_types)

DeviceState *apple_modern_disp0_new(const AppleModernDisp0Plan *plan,
                                    MemoryRegion *ram,
                                    uint64_t framebuffer_offset,
                                    uint32_t width, uint32_t height,
                                    uint32_t stride, Chardev *uart)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_DISP0);
    AppleModernDisp0State *s = APPLE_MODERN_DISP0(dev);

    s->core.plan = *plan;
    /*
     * The version register's value is declared, not attested. t8030's model
     * answers 0x70045 ("A1"); this reports a value that is plainly not a real
     * t8140 silicon revision so a guest that checks it cannot be told it is
     * running on hardware we have not modelled.
     */
    s->core.version = 0;
    object_property_set_link(OBJECT(dev), "ram", OBJECT(ram), &error_abort);
    qdev_prop_set_uint64(dev, "framebuffer-offset", framebuffer_offset);
    qdev_prop_set_uint32(dev, "width", width);
    qdev_prop_set_uint32(dev, "height", height);
    qdev_prop_set_uint32(dev, "stride", stride);
    object_property_set_link(OBJECT(dev), "uart", OBJECT(uart), &error_abort);
    return dev;
}
#endif
