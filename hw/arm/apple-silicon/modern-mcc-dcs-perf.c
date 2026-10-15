/* T8140 DCS performance configuration, command completion and counters.
 * Register geometry comes from the matched ADT and guest descriptors. Counter
 * reset/enable semantics are a declared functional model inferred from the
 * driver's request/poll/enable sequence. No physical event source is attached.
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
        error_setg(errp, "DCS performance output aliases input or invalid exclusions");
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
    if (!apple_modern_mcc_dramcfg_plan_build(tree, dram_base, dram_size,
                                             NULL, 0, &geometry, errp)) {
        return false;
    }
    for (unsigned view = 0; view < APPLE_MODERN_DCS_PERF_VIEWS; view++) {
        uint64_t base = geometry.addresses[view / 2] - APPLE_MODERN_MCC_DRAMCFG_OFFSET;
        uint64_t address = base + (view % 2 ? APPLE_MODERN_DCS_PERF_COUNTER_OFFSET :
                                               APPLE_MODERN_DCS_PERF_CONTROL_OFFSET);
        uint64_t span = view % 2 ? APPLE_MODERN_DCS_PERF_COUNTERS * 8 :
                                  APPLE_MODERN_DCS_PERF_CONTROLS * 4;
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
    for (unsigned bank = 0; bank < APPLE_MODERN_MCC_DCS_COUNT; bank++) {
        for (unsigned i = 0; i < APPLE_MODERN_DCS_PERF_COUNTERS; i++) {
            core->values[bank][i] = core->reset_value;
        }
    }
    core->reads = core->writes = core->clears = core->event_updates = 0;
}

static bool valid_access(unsigned view, uint64_t offset, unsigned size)
{
    unsigned width = view % 2 ? 8 : 4;
    unsigned span = view % 2 ? APPLE_MODERN_DCS_PERF_COUNTERS * 8 :
                               APPLE_MODERN_DCS_PERF_CONTROLS * 4;
    return view < APPLE_MODERN_DCS_PERF_VIEWS && size == width &&
           !(offset & (width - 1)) && offset < span;
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
    if (!core || !valid_access(view, offset, size) || view % 2) {
        return false;
    }
    unsigned bank = view / 2;
    uint32_t word = value;
    if (offset == 0) { /* +0x580: channel mask[13:4], request[0]. */
        if ((word & ~0x3ff1U) || (word && !(word & 1))) {
            return false;
        }
        for (unsigned i = 0; i < 10; i++) {
            if (word & (1U << (i + 4))) {
                core->values[bank][i] = 0;
                increment(&core->clears);
            }
        }
        /* The command completes synchronously after clearing selected state. */
        word = 0;
    } else if (offset == 8) { /* +0x588: duration enable + reset requests. */
        for (unsigned i = 0; i < 4; i++) {
            if (word & (1U << (16 + 4 * i))) {
                core->values[bank][10 + i] = 0;
                increment(&core->clears);
            }
        }
        /* XNU polls the high request bits until completion before enabling. */
        word &= ~0x11110000U;
    }
    core->controls[bank][offset / 4] = word;
    increment(&core->writes);
    return true;
}

bool apple_modern_dcs_perf_core_event(AppleModernDCSPERFCore *core,
    unsigned bank, unsigned counter, uint64_t amount)
{
    if (!core || bank >= APPLE_MODERN_MCC_DCS_COUNT ||
        counter >= APPLE_MODERN_DCS_PERF_COUNTERS) {
        return false;
    }
    uint32_t enables = core->controls[bank][counter < 10 ? 1 : 2];
    unsigned bit = counter < 10 ? counter : 4 * (counter - 10);
    if (amount && (enables & (1U << bit))) {
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
    return apple_modern_dcs_perf_core_read(view->core, view->index, offset, size, value) ?
           MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static MemTxResult perf_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size, MemTxAttrs attrs)
{
    DCSPERFView *view = opaque;
    return apple_modern_dcs_perf_core_write(view->core, view->index, offset, size, value) ?
           MEMTX_OK : MEMTX_ACCESS_ERROR;
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
        memory_region_init_io(&s->regions[i], OBJECT(dev), i % 2 ? &counter_ops : &control_ops,
            &s->views[i], "apple-modern.mcc-dcs-perf",
            i % 2 ? APPLE_MODERN_DCS_PERF_COUNTERS * 8 : APPLE_MODERN_DCS_PERF_CONTROLS * 4);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque, Error **errp)
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
    object_class_property_add(oc, "counter-clear-count", "uint64", get_counter, NULL, NULL,
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
static const TypeInfo perf_type = {
    .name = TYPE_APPLE_MODERN_DCS_PERF, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernDCSPERFState), .class_init = perf_class_init,
};
static void register_types(void) { type_register_static(&perf_type); }
type_init(register_types)
#endif
