/* T8140 AMCC system-level-cache way and flush control.
 * Cells, widths and the polled fields are those of the pinned BootKC's
 * mccEnableCacheMode, mccWaitForWaysPwrOn and cacheFlush. The way-count
 * echo and the 12-way handover state match m1n1 PR #664's per-plane
 * readback on t604x/t8140-family Macs (analogy). Broadcast of the global writes and
 * immediate power-up/flush completion are a declared functional profile;
 * no cache, power or timing model is attached.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
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
#include "migration/vmstate.h"
#endif
#include "hw/arm/apple-silicon/modern-mcc-slc.h"

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

static bool aliases(const void *a, size_t as, const void *b, size_t bs)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return as && bs && (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y ||
                       (x < y + bs && y < x + as));
}

/* An optional /arm-io/mcc property that changes which cells the driver uses
 * is accepted only when absent or equal to the default this model mirrors.
 * The tree itself was already validated, so a failed lookup means absent. */
static bool optional_property(AppleModernBlob tree, const char *device,
                              const char *name, uint32_t limit, bool exact,
                              Error **errp)
{
    AppleModernBlob property;
    Error *absent = NULL;
    if (!apple_modern_adt_property(tree, "/arm-io/mcc", name, &property, &absent)) {
        error_free(absent);
        return true;
    }
    if (property.size != 4) {
        error_setg(errp, "%s: MCC %s has %zu bytes, expected 4", device, name,
                   property.size);
        return false;
    }
    uint32_t value = 0;
    for (size_t i = 0; i < 4; i++) {
        value |= (uint32_t)property.data[i] << (8 * i);
    }
    if (exact ? value != limit : value > limit) {
        error_setg(errp, "%s: MCC %s=%#x is not modelled", device, name, value);
        return false;
    }
    return true;
}

uint64_t apple_modern_mcc_slc_view_offset(unsigned view)
{
    if (view >= APPLE_MODERN_MCC_SLC_VIEWS) {
        return UINT64_MAX;
    }
    static const uint32_t global[APPLE_MODERN_MCC_SLC_GLOBAL_VIEWS] = {
        APPLE_MODERN_MCC_SLC_WAYS, APPLE_MODERN_MCC_SLC_CTRL_82C,
        APPLE_MODERN_MCC_SLC_FLUSH,
    };
    if (view < APPLE_MODERN_MCC_SLC_GLOBAL_VIEWS) {
        return APPLE_MODERN_MCC_SLC_GLOBAL_OFFSET + global[view];
    }
    if (view < APPLE_MODERN_MCC_SLC_FLUSH_VIEW) {
        return (uint64_t)(view - APPLE_MODERN_MCC_SLC_STATUS_VIEW) *
               APPLE_MODERN_MCC_SLC_PLANE_STRIDE + APPLE_MODERN_MCC_SLC_WAY_STATUS;
    }
    return (uint64_t)(view - APPLE_MODERN_MCC_SLC_FLUSH_VIEW) *
           APPLE_MODERN_MCC_SLC_PLANE_STRIDE + APPLE_MODERN_MCC_SLC_FLUSH;
}

bool apple_modern_mcc_slc_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCSLCPlan *output, Error **errp)
{
    AppleModernMCCQuotaPlan geometry;
    AppleModernMCCSLCPlan plan = {0};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "MCC SLC output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "MCC SLC exclusion is empty or wraps");
            return false;
        }
    }
    /* Reuse the matched amcc-reg-idx/reg[2]/ranges validation. */
    if (!apple_modern_mcc_quota_plan_build(tree, dram_base, dram_size,
                                          NULL, 0, &geometry, errp) ||
        !optional_property(tree, "MCC SLC", "amcc-plane-enable-mask", 0xf, true,
                           errp) ||
        /* The driver's way count is capped by max-way-count (default 12);
         * the status fields hold seven bits. */
        !optional_property(tree, "MCC SLC", "max-way-count", APPLE_MODERN_MCC_SLC_WAY_MASK,
                           false, errp)) {
        return false;
    }
    uint64_t amcc = geometry.addresses[0] - APPLE_MODERN_MCC_QUOTA_OFFSET;
    for (unsigned view = 0; view < APPLE_MODERN_MCC_SLC_VIEWS; view++) {
        uint64_t address = amcc + apple_modern_mcc_slc_view_offset(view);
        if (apple_modern_mcc_slc_view_offset(view) + APPLE_MODERN_MCC_SLC_SPAN >
                APPLE_MODERN_MCC_AMCC_SPAN) {
            error_setg(errp, "MCC SLC view lies outside the AMCC window");
            return false;
        }
        if (address < dram_base + dram_size &&
            dram_base < address + APPLE_MODERN_MCC_SLC_SPAN) {
            error_setg(errp, "MCC SLC view overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + APPLE_MODERN_MCC_SLC_SPAN) {
                error_setg(errp, "MCC SLC view overlaps another device");
                return false;
            }
        }
        plan.addresses[view] = address;
    }
    *output = plan;
    return true;
}

static void increment(uint64_t *value)
{
    if (*value != UINT64_MAX) {
        (*value)++;
    }
}

void apple_modern_mcc_slc_core_reset(AppleModernMCCSLCCore *core)
{
    core->ways = APPLE_MODERN_MCC_SLC_RESET_WAYS;
    core->ctrl_82c = core->flush = 0;
    core->reads = core->writes = 0;
}

static bool valid_access(unsigned view, uint64_t offset, unsigned size)
{
    return view < APPLE_MODERN_MCC_SLC_VIEWS && size == 4 && !offset;
}

bool apple_modern_mcc_slc_core_read(AppleModernMCCSLCCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value)
{
    /* No driver load of a global cell is observed. */
    if (!core || !value || !valid_access(view, offset, size) ||
        view < APPLE_MODERN_MCC_SLC_GLOBAL_VIEWS ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    if (view < APPLE_MODERN_MCC_SLC_FLUSH_VIEW) {
        uint32_t ways = core->ways & APPLE_MODERN_MCC_SLC_WAY_MASK;
        *value = (ways << 24) | (ways << 8);
    } else {
        *value = 0;
    }
    increment(&core->reads);
    return true;
}

bool apple_modern_mcc_slc_core_write(AppleModernMCCSLCCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value)
{
    /* The driver only loads the plane status cells. */
    if (!core || !valid_access(view, offset, size) ||
        view >= APPLE_MODERN_MCC_SLC_GLOBAL_VIEWS) {
        return false;
    }
    uint32_t *cells[APPLE_MODERN_MCC_SLC_GLOBAL_VIEWS] = {
        &core->ways, &core->ctrl_82c, &core->flush,
    };
    *cells[view] = value;
    increment(&core->writes);
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct SLCView {
    AppleModernMCCSLCCore *core;
    unsigned index;
} SLCView;
struct AppleModernMCCSLCState {
    SysBusDevice parent_obj;
    AppleModernMCCSLCCore core;
    SLCView views[APPLE_MODERN_MCC_SLC_VIEWS];
    MemoryRegion regions[APPLE_MODERN_MCC_SLC_VIEWS];
};
static MemTxResult slc_read(void *opaque, hwaddr offset, uint64_t *value,
                            unsigned size, MemTxAttrs attrs)
{
    SLCView *view = opaque;
    return apple_modern_mcc_slc_core_read(view->core, view->index, offset,
                                          size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static MemTxResult slc_write(void *opaque, hwaddr offset, uint64_t value,
                             unsigned size, MemTxAttrs attrs)
{
    SLCView *view = opaque;
    return apple_modern_mcc_slc_core_write(view->core, view->index, offset,
                                           size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps slc_ops = {
    .read_with_attrs = slc_read, .write_with_attrs = slc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};
static void slc_reset(DeviceState *dev)
{
    apple_modern_mcc_slc_core_reset(&APPLE_MODERN_MCC_SLC(dev)->core);
}
static void slc_realize(DeviceState *dev, Error **errp)
{
    AppleModernMCCSLCState *s = APPLE_MODERN_MCC_SLC(dev);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SLC_VIEWS; i++) {
        s->views[i] = (SLCView){&s->core, i};
        memory_region_init_io(&s->regions[i], OBJECT(dev), &slc_ops, &s->views[i],
                              "apple-modern.mcc-slc", APPLE_MODERN_MCC_SLC_SPAN);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernMCCSLCCore *core = &APPLE_MODERN_MCC_SLC(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static void get_cell(Object *obj, Visitor *v, const char *name, void *opaque,
                     Error **errp)
{
    AppleModernMCCSLCCore *core = &APPLE_MODERN_MCC_SLC(obj)->core;
    uint32_t value = *(uint32_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint32(v, name, &value, errp);
}
static const VMStateDescription slc_unmigratable = {
    .name = TYPE_APPLE_MODERN_MCC_SLC, .unmigratable = 1,
};
static void slc_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = slc_realize;
    dc->vmsd = &slc_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, slc_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernMCCSLCCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernMCCSLCCore, writes));
    object_class_property_add(oc, "requested-ways", "uint32", get_cell, NULL, NULL,
        (void *)offsetof(AppleModernMCCSLCCore, ways));
    object_class_property_add(oc, "control-82c", "uint32", get_cell, NULL, NULL,
        (void *)offsetof(AppleModernMCCSLCCore, ctrl_82c));
    object_class_property_add(oc, "flush-request", "uint32", get_cell, NULL, NULL,
        (void *)offsetof(AppleModernMCCSLCCore, flush));
}
DeviceState *apple_modern_mcc_slc_new(void)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_MCC_SLC);
    slc_reset(dev);
    return dev;
}
static const TypeInfo slc_type = {
    .name = TYPE_APPLE_MODERN_MCC_SLC, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernMCCSLCState), .class_init = slc_class_init,
};
static void register_types(void) { type_register_static(&slc_type); }
type_init(register_types)
#endif
