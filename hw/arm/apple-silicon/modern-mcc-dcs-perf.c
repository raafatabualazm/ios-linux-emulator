/* T8140 DCS performance controls and counters.
 * Geometry is matched against the ADT (dcs-reg-idx, reg[8..11]; DCS3 is
 * validated but not mapped) and the
 * pinned BootKC's descriptor table and register helpers: 32-bit controls
 * written by plain stores or (old & ~mask) | (value & mask), 64-bit counter
 * loads, and a +0x588 "clear bit" the driver polls until it reads zero (ten
 * reads, ~20 us, then "Failed to clear DCS perf counter %s clear bit"). All
 * effects beyond that contract are a declared functional profile; no
 * physical event source is attached.
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
#include "hw/arm/apple-silicon/modern-mcc-dcs-perf.h"

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
    return view % 2 ? 8 : 4;
}

static uint64_t view_span(unsigned view)
{
    return view % 2 ? APPLE_MODERN_DCS_PERF_COUNTERS * 8 :
                      APPLE_MODERN_DCS_PERF_CONTROLS * 4;
}

bool apple_modern_dcs_perf_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDCSPERFPlan *output, Error **errp)
{
    AppleModernMCCDRAMCFGPlan geometry;
    AppleModernDCSPERFPlan plan = {0};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "DCS performance output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "DCS performance exclusion is empty or wraps");
            return false;
        }
    }
    /* Reuse the matched dcs-reg-idx/reg/ranges validation; its single words
     * at +0x1d48 lie outside both views, so they are not exclusions here. */
    if (!apple_modern_mcc_dramcfg_plan_build(tree, dram_base, dram_size,
                                             NULL, 0, &geometry, errp) ||
        /* Both masks default to 0xf; they gate which units are mapped and
         * the kind-3 sample factor (32 * popcount). */
        !optional_property(tree, "DCS performance", "dcs-channel-enable-mask",
                           0xf, true, errp) ||
        !optional_property(tree, "DCS performance", "amcc-plane-enable-mask",
                           0xf, true, errp)) {
        return false;
    }
    for (unsigned view = 0; view < APPLE_MODERN_DCS_PERF_VIEWS; view++) {
        uint64_t base = geometry.addresses[view / 2] - APPLE_MODERN_MCC_DRAMCFG_OFFSET;
        uint64_t address = base + (view % 2 ? APPLE_MODERN_DCS_PERF_COUNTER_OFFSET :
                                               APPLE_MODERN_DCS_PERF_CONTROL_OFFSET);
        uint64_t span = view_span(view);
        if (address < dram_base + dram_size && dram_base < address + span) {
            error_setg(errp, "DCS performance view overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + span) {
                error_setg(errp, "DCS performance view overlaps another device");
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

void apple_modern_dcs_perf_core_reset(AppleModernDCSPERFCore *core)
{
    memset(core->controls, 0, sizeof(core->controls));
    for (unsigned bank = 0; bank < APPLE_MODERN_DCS_PERF_BANKS; bank++) {
        for (unsigned i = 0; i < APPLE_MODERN_DCS_PERF_COUNTERS; i++) {
            core->values[bank][i] = core->reset_value;
        }
    }
    core->reads = core->writes = core->clears = core->event_updates = 0;
}

static bool valid_access(unsigned view, uint64_t offset, unsigned size)
{
    return view < APPLE_MODERN_DCS_PERF_VIEWS && size == view_width(view) &&
           !(offset & (size - 1)) && offset < view_span(view);
}

bool apple_modern_dcs_perf_core_read(AppleModernDCSPERFCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value)
{
    if (!core || !value || !valid_access(view, offset, size) ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    *value = view % 2 ? core->values[view / 2][offset / 8] :
                        core->controls[view / 2][offset / 4];
    increment(&core->reads);
    return true;
}

bool apple_modern_dcs_perf_core_write(AppleModernDCSPERFCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value)
{
    /* The driver never stores to a counter. */
    if (!core || !valid_access(view, offset, size) || view % 2) {
        return false;
    }
    unsigned bank = view / 2;
    uint32_t word = value;
    if (offset == APPLE_MODERN_DCS_PERF_DURATION_CONTROL) {
        for (unsigned i = 0; i < APPLE_MODERN_DCS_PERF_DURATIONS; i++) {
            if (word & (1U << (16 + 4 * i))) {
                /* Inferred, not attested: the clear bit zeroes duration
                 * counter i (consistent with the driver's panic name and
                 * its baseline carry at 0xfffffff0098265e4 when a counter
                 * reads lower after a disable); completion timing is not
                 * attested either. Zero, not reset_value, is written. */
                core->values[bank][APPLE_MODERN_DCS_PERF_EVENTS + i] = 0;
                increment(&core->clears);
            }
        }
        word &= ~APPLE_MODERN_DCS_PERF_CLEAR_BITS;
    }
    core->controls[bank][offset / 4] = word;
    increment(&core->writes);
    return true;
}

bool apple_modern_dcs_perf_core_event(AppleModernDCSPERFCore *core,
    unsigned bank, unsigned counter, uint64_t amount)
{
    if (!core || bank >= APPLE_MODERN_DCS_PERF_BANKS ||
        counter >= APPLE_MODERN_DCS_PERF_COUNTERS) {
        return false;
    }
    bool events = counter < APPLE_MODERN_DCS_PERF_EVENTS;
    uint32_t enables = core->controls[bank][(events ? APPLE_MODERN_DCS_PERF_EVENT_ENABLE :
                                             APPLE_MODERN_DCS_PERF_DURATION_CONTROL) / 4];
    unsigned bit = events ? counter : 4 * (counter - APPLE_MODERN_DCS_PERF_EVENTS);
    if (amount && (enables & (1U << bit))) {
        /* Unsigned modulo-64 accumulation is a virtual choice. */
        core->values[bank][counter] += amount;
        increment(&core->event_updates);
    }
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct DCSPERFView {
    AppleModernDCSPERFCore *core;
    unsigned index;
} DCSPERFView;
struct AppleModernDCSPERFState {
    SysBusDevice parent_obj;
    AppleModernDCSPERFCore core;
    DCSPERFView views[APPLE_MODERN_DCS_PERF_VIEWS];
    MemoryRegion regions[APPLE_MODERN_DCS_PERF_VIEWS];
};
static MemTxResult perf_read(void *opaque, hwaddr offset, uint64_t *value,
                             unsigned size, MemTxAttrs attrs)
{
    DCSPERFView *view = opaque;
    return apple_modern_dcs_perf_core_read(view->core, view->index, offset,
                                           size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static MemTxResult perf_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size, MemTxAttrs attrs)
{
    DCSPERFView *view = opaque;
    return apple_modern_dcs_perf_core_write(view->core, view->index, offset,
                                            size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps control_ops = {
    .read_with_attrs = perf_read, .write_with_attrs = perf_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};
static const MemoryRegionOps counter_ops = {
    .read_with_attrs = perf_read, .write_with_attrs = perf_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 8, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 8, .max_access_size = 8},
};
static void perf_reset(DeviceState *dev)
{
    apple_modern_dcs_perf_core_reset(&APPLE_MODERN_DCS_PERF(dev)->core);
}
static void perf_realize(DeviceState *dev, Error **errp)
{
    AppleModernDCSPERFState *s = APPLE_MODERN_DCS_PERF(dev);
    for (unsigned i = 0; i < APPLE_MODERN_DCS_PERF_VIEWS; i++) {
        s->views[i] = (DCSPERFView){&s->core, i};
        memory_region_init_io(&s->regions[i], OBJECT(dev),
            i % 2 ? &counter_ops : &control_ops, &s->views[i],
            "apple-modern.mcc-dcs-perf", view_span(i));
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernDCSPERFCore *core = &APPLE_MODERN_DCS_PERF(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription perf_unmigratable = {
    .name = TYPE_APPLE_MODERN_DCS_PERF, .unmigratable = 1,
};
static void perf_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = perf_realize;
    dc->vmsd = &perf_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, perf_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDCSPERFCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDCSPERFCore, writes));
    object_class_property_add(oc, "clear-request-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDCSPERFCore, clears));
    object_class_property_add(oc, "event-update-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDCSPERFCore, event_updates));
}
DeviceState *apple_modern_dcs_perf_new(uint64_t reset_value)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_DCS_PERF);
    APPLE_MODERN_DCS_PERF(dev)->core.reset_value = reset_value;
    perf_reset(dev);
    return dev;
}
bool apple_modern_dcs_perf_event(DeviceState *dev, unsigned bank,
                                 unsigned counter, uint64_t amount)
{
    return dev && apple_modern_dcs_perf_core_event(&APPLE_MODERN_DCS_PERF(dev)->core,
                                                   bank, counter, amount);
}
static const TypeInfo perf_type = {
    .name = TYPE_APPLE_MODERN_DCS_PERF, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernDCSPERFState), .class_init = perf_class_init,
};
static void register_types(void) { type_register_static(&perf_type); }
type_init(register_types)
#endif
