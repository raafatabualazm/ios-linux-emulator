/* T8140 AMCC DSID profile controls and plane-0 hit/miss counters.
 * The cells, widths and written values are those of the pinned BootKC's
 * enableDsidProfileCounters and perf slot 3 (kind 2, read64 only). Only the
 * +0x2a008 values derive from /arm-io/pmp/iop-pmp-nub mc-dsid-ptd-config;
 * +0x2a010 = 0x10000000, +0x2e000 = 0x100 and +0x2a000 = 0x11 then 0x1 are
 * driver constants. "First plane" is the lowest set bit of
 * amcc-plane-enable-mask, which defaults to 0xf (plane 0).
 * Bit meanings, reset contents and any counting behaviour are a declared
 * functional profile; no physical event source is attached.
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
#include "hw/arm/apple-silicon/modern-mcc-dsid.h"

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

static unsigned view_width(unsigned view)
{
    return view >= APPLE_MODERN_MCC_DSID_INTERVAL_VIEW &&
           view < APPLE_MODERN_MCC_DSID_COUNTER_VIEW ? 4 : 8;
}

uint64_t apple_modern_mcc_dsid_view_span(unsigned view)
{
    if (view < APPLE_MODERN_MCC_DSID_INTERVAL_VIEW) {
        /* +0x2a010 is written on the first plane only. */
        return view ? 2 * 8 : APPLE_MODERN_MCC_DSID_CONTROLS * 8;
    }
    if (view < APPLE_MODERN_MCC_DSID_COUNTER_VIEW) {
        return 4;
    }
    return view == APPLE_MODERN_MCC_DSID_COUNTER_VIEW ?
           APPLE_MODERN_MCC_DSID_COUNTERS * 8 : 0;
}

static uint64_t view_offset(unsigned view)
{
    if (view < APPLE_MODERN_MCC_DSID_INTERVAL_VIEW) {
        return (uint64_t)view * APPLE_MODERN_MCC_DSID_PLANE_STRIDE +
               APPLE_MODERN_MCC_DSID_CONTROL_OFFSET;
    }
    if (view < APPLE_MODERN_MCC_DSID_COUNTER_VIEW) {
        return (uint64_t)(view - APPLE_MODERN_MCC_DSID_INTERVAL_VIEW) *
               APPLE_MODERN_MCC_DSID_PLANE_STRIDE + APPLE_MODERN_MCC_DSID_INTERVAL_OFFSET;
    }
    return APPLE_MODERN_MCC_DSID_COUNTER_OFFSET;
}

bool apple_modern_mcc_dsid_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCDSIDPlan *output, Error **errp)
{
    AppleModernMCCQuotaPlan geometry;
    AppleModernMCCDSIDPlan plan = {0};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "MCC DSID output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "MCC DSID exclusion is empty or wraps");
            return false;
        }
    }
    /* Reuse the matched amcc-reg-idx/reg[2]/ranges validation; the quota
     * banks lie outside these views, so they are not exclusions here. */
    if (!apple_modern_mcc_quota_plan_build(tree, dram_base, dram_size,
                                          NULL, 0, &geometry, errp) ||
        !optional_property(tree, "MCC DSID", "amcc-plane-enable-mask", 0xf, true,
                           errp)) {
        return false;
    }
    uint64_t amcc = geometry.addresses[0] - APPLE_MODERN_MCC_QUOTA_OFFSET;
    for (unsigned view = 0; view < APPLE_MODERN_MCC_DSID_VIEWS; view++) {
        uint64_t address = amcc + view_offset(view);
        uint64_t span = apple_modern_mcc_dsid_view_span(view);
        if (view_offset(view) + span > APPLE_MODERN_MCC_AMCC_SPAN) {
            error_setg(errp, "MCC DSID view lies outside the AMCC window");
            return false;
        }
        if (address < dram_base + dram_size && dram_base < address + span) {
            error_setg(errp, "MCC DSID view overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + span) {
                error_setg(errp, "MCC DSID view overlaps another device");
                return false;
            }
        }
        plan.addresses[view] = address;
        plan.spans[view] = span;
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

void apple_modern_mcc_dsid_core_reset(AppleModernMCCDSIDCore *core)
{
    memset(core->controls, 0, sizeof(core->controls));
    memset(core->intervals, 0, sizeof(core->intervals));
    for (unsigned i = 0; i < APPLE_MODERN_MCC_DSID_COUNTERS; i++) {
        core->values[i] = core->reset_value;
    }
    core->reads = core->writes = core->event_updates = 0;
}

static bool valid_access(unsigned view, uint64_t offset, unsigned size)
{
    return view < APPLE_MODERN_MCC_DSID_VIEWS && size == view_width(view) &&
           !(offset & (size - 1)) && offset < apple_modern_mcc_dsid_view_span(view);
}

bool apple_modern_mcc_dsid_core_read(AppleModernMCCDSIDCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value)
{
    if (!core || !value || !valid_access(view, offset, size) ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    if (view < APPLE_MODERN_MCC_DSID_INTERVAL_VIEW) {
        *value = core->controls[view][offset / 8];
    } else if (view < APPLE_MODERN_MCC_DSID_COUNTER_VIEW) {
        *value = core->intervals[view - APPLE_MODERN_MCC_DSID_INTERVAL_VIEW];
    } else {
        *value = core->values[offset / 8];
    }
    increment(&core->reads);
    return true;
}

bool apple_modern_mcc_dsid_core_write(AppleModernMCCDSIDCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value)
{
    /* The driver only loads the counters. */
    if (!core || !valid_access(view, offset, size) ||
        view == APPLE_MODERN_MCC_DSID_COUNTER_VIEW) {
        return false;
    }
    if (view < APPLE_MODERN_MCC_DSID_INTERVAL_VIEW) {
        core->controls[view][offset / 8] = value;
    } else {
        core->intervals[view - APPLE_MODERN_MCC_DSID_INTERVAL_VIEW] = value;
    }
    increment(&core->writes);
    return true;
}

bool apple_modern_mcc_dsid_core_event(AppleModernMCCDSIDCore *core,
    unsigned counter, uint64_t amount)
{
    if (!core || counter >= APPLE_MODERN_MCC_DSID_COUNTERS) {
        return false;
    }
    if (amount && (core->controls[0][0] & 1)) {
        /* Unsigned modulo-64 accumulation is a virtual choice. */
        core->values[counter] += amount;
        increment(&core->event_updates);
    }
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct DSIDView {
    AppleModernMCCDSIDCore *core;
    unsigned index;
} DSIDView;
struct AppleModernMCCDSIDState {
    SysBusDevice parent_obj;
    AppleModernMCCDSIDCore core;
    DSIDView views[APPLE_MODERN_MCC_DSID_VIEWS];
    MemoryRegion regions[APPLE_MODERN_MCC_DSID_VIEWS];
};
static MemTxResult dsid_read(void *opaque, hwaddr offset, uint64_t *value,
                             unsigned size, MemTxAttrs attrs)
{
    DSIDView *view = opaque;
    return apple_modern_mcc_dsid_core_read(view->core, view->index, offset,
                                           size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static MemTxResult dsid_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size, MemTxAttrs attrs)
{
    DSIDView *view = opaque;
    return apple_modern_mcc_dsid_core_write(view->core, view->index, offset,
                                            size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps word_ops = {
    .read_with_attrs = dsid_read, .write_with_attrs = dsid_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};
static const MemoryRegionOps doubleword_ops = {
    .read_with_attrs = dsid_read, .write_with_attrs = dsid_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 8, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 8, .max_access_size = 8},
};
static void dsid_reset(DeviceState *dev)
{
    apple_modern_mcc_dsid_core_reset(&APPLE_MODERN_MCC_DSID(dev)->core);
}
static void dsid_realize(DeviceState *dev, Error **errp)
{
    AppleModernMCCDSIDState *s = APPLE_MODERN_MCC_DSID(dev);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_DSID_VIEWS; i++) {
        s->views[i] = (DSIDView){&s->core, i};
        memory_region_init_io(&s->regions[i], OBJECT(dev),
            view_width(i) == 4 ? &word_ops : &doubleword_ops, &s->views[i],
            "apple-modern.mcc-dsid", apple_modern_mcc_dsid_view_span(i));
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernMCCDSIDCore *core = &APPLE_MODERN_MCC_DSID(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription dsid_unmigratable = {
    .name = TYPE_APPLE_MODERN_MCC_DSID, .unmigratable = 1,
};
static void dsid_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = dsid_realize;
    dc->vmsd = &dsid_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, dsid_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernMCCDSIDCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernMCCDSIDCore, writes));
    object_class_property_add(oc, "event-update-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernMCCDSIDCore, event_updates));
}
DeviceState *apple_modern_mcc_dsid_new(uint64_t reset_value)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_MCC_DSID);
    APPLE_MODERN_MCC_DSID(dev)->core.reset_value = reset_value;
    dsid_reset(dev);
    return dev;
}
bool apple_modern_mcc_dsid_event(DeviceState *dev, unsigned counter, uint64_t amount)
{
    return dev && apple_modern_mcc_dsid_core_event(&APPLE_MODERN_MCC_DSID(dev)->core,
                                                   counter, amount);
}
static const TypeInfo dsid_type = {
    .name = TYPE_APPLE_MODERN_MCC_DSID, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernMCCDSIDState), .class_init = dsid_class_init,
};
static void register_types(void) { type_register_static(&dsid_type); }
type_init(register_types)
#endif
