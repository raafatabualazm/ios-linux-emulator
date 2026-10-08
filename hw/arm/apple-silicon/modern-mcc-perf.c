/* Sparse T8140 AMCC performance channels with a declared virtual profile.
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
#include "hw/arm/apple-silicon/modern-mcc-perf.h"

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

static bool scalar(AppleModernBlob tree, const char *name, uint32_t expected,
                   Error **errp)
{
    AppleModernBlob property;
    if (!apple_modern_adt_property(tree, "/arm-io/mcc", name, &property, errp)) {
        return false;
    }
    if (property.size != 4 || little(property.data, 4) != expected) {
        error_setg(errp, "MCC perf requires matched T8140 %s=%u", name, expected);
        return false;
    }
    return true;
}

bool apple_modern_mcc_perf_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCPerfPlan *output, Error **errp)
{
    AppleModernBlob compatible, reg, ranges;
    AppleModernMCCPerfPlan plan = {0};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "MCC perf output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "MCC perf DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "MCC perf exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io/mcc", "compatible", &compatible, errp) ||
        !scalar(tree, "amcc-reg-idx", 2, errp) ||
        !scalar(tree, "dcs-count-per-amcc", 4, errp) ||
        !scalar(tree, "amcc-count", 1, errp) ||
        !apple_modern_adt_property(tree, "/arm-io/mcc", "reg", &reg, errp) ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (compatible.size != sizeof("mcc,t8140") ||
        memcmp(compatible.data, "mcc,t8140", sizeof("mcc,t8140")) ||
        reg.size != 12 * 16 || !ranges.size || ranges.size % 24 ||
        little(reg.data + 2 * 16, 8) != UINT64_C(0x10000000) ||
        little(reg.data + 2 * 16 + 8, 8) != 0x140000) {
        error_setg(errp, "MCC perf requires the matched T8140 AMCC schema");
        return false;
    }
    unsigned matches = 0;
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t c = little(ranges.data + i, 8);
        uint64_t p = little(ranges.data + i + 8, 8);
        uint64_t n = little(ranges.data + i + 16, 8);
        if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
            error_setg(errp, "MCC perf bus range is empty or wraps");
            return false;
        }
        if (UINT64_C(0x10000000) >= c && UINT64_C(0x10000000) - c <= n &&
            0x140000 <= n - (UINT64_C(0x10000000) - c)) {
            if (p + (UINT64_C(0x10000000) - c) != UINT64_C(0x220000000)) {
                error_setg(errp, "MCC perf AMCC translation disagrees");
                return false;
            }
            matches++;
        }
    }
    if (matches != 1) {
        error_setg(errp, "MCC perf AMCC translation is missing or ambiguous");
        return false;
    }
    for (unsigned view = 0; view < APPLE_MODERN_MCC_PERF_VIEWS; view++) {
        uint64_t address = UINT64_C(0x220000000) +
            (uint64_t)(view / 2) * APPLE_MODERN_MCC_PERF_BANK_STRIDE +
            (view % 2 ? APPLE_MODERN_MCC_PERF_COUNTER_OFFSET :
                        APPLE_MODERN_MCC_PERF_CONTROL_OFFSET);
        uint64_t span = view % 2 ? APPLE_MODERN_MCC_PERF_COUNTER_SPAN : 8;
        if (address < dram_base + dram_size && dram_base < address + span) {
            error_setg(errp, "MCC perf view overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + span) {
                error_setg(errp, "MCC perf view overlaps another device");
                return false;
            }
        }
        plan.addresses[view] = address;
    }
    *output = plan;
    return true;
}

void apple_modern_mcc_perf_core_reset(AppleModernMCCPerfCore *core)
{
    memset(core->controls, 0, sizeof(core->controls));
    for (unsigned bank = 0; bank < APPLE_MODERN_MCC_PERF_BANKS; bank++) {
        for (unsigned index = 0; index < APPLE_MODERN_MCC_PERF_COUNTERS; index++) {
            core->values[bank][index] = core->reset_value;
        }
    }
    core->reads = core->writes = core->event_updates = 0;
}

static bool valid_offset(unsigned view, uint64_t offset)
{
    return !(offset & 7) && (view % 2 ?
        offset < APPLE_MODERN_MCC_PERF_COUNTER_SPAN : offset == 0);
}

bool apple_modern_mcc_perf_core_read(AppleModernMCCPerfCore *core,
    unsigned view, uint64_t offset, uint64_t *value)
{
    if (!core || view >= APPLE_MODERN_MCC_PERF_VIEWS ||
        !valid_offset(view, offset) || !value ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    *value = view % 2 ? core->values[view / 2][offset / 8] :
                       core->controls[view / 2];
    if (core->reads != UINT64_MAX) {
        core->reads++;
    }
    return true;
}

bool apple_modern_mcc_perf_core_write(AppleModernMCCPerfCore *core,
    unsigned view, uint64_t offset, uint64_t value)
{
    /* Counter writability/clear behavior is not established. Reject writes. */
    if (!core || view >= APPLE_MODERN_MCC_PERF_VIEWS || view % 2 || offset) {
        return false;
    }
    core->controls[view / 2] = value;
    if (core->writes != UINT64_MAX) {
        core->writes++;
    }
    return true;
}

bool apple_modern_mcc_perf_core_event(AppleModernMCCPerfCore *core,
    unsigned bank, unsigned counter, uint64_t amount)
{
    if (!core || bank >= APPLE_MODERN_MCC_PERF_BANKS ||
        counter >= APPLE_MODERN_MCC_PERF_COUNTERS) {
        return false;
    }
    if (amount && (core->controls[bank] & (UINT64_C(1) << counter))) {
        /* Deliberate unsigned modulo-64 virtual arithmetic, not silicon width. */
        core->values[bank][counter] += amount;
        if (core->event_updates != UINT64_MAX) {
            core->event_updates++;
        }
    }
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct PerfView {
    AppleModernMCCPerfCore *core;
    unsigned index;
} PerfView;
struct AppleModernMCCPerfState {
    SysBusDevice parent_obj;
    AppleModernMCCPerfCore core;
    PerfView views[APPLE_MODERN_MCC_PERF_VIEWS];
    MemoryRegion regions[APPLE_MODERN_MCC_PERF_VIEWS];
};
static MemTxResult perf_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    PerfView *view = opaque;
    return size == 8 && apple_modern_mcc_perf_core_read(view->core,
        view->index, offset, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static MemTxResult perf_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    PerfView *view = opaque;
    return size == 8 && apple_modern_mcc_perf_core_write(view->core,
        view->index, offset, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps perf_ops = {
    .read_with_attrs = perf_read, .write_with_attrs = perf_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 8, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 8, .max_access_size = 8},
};
static void perf_reset(DeviceState *dev)
{
    apple_modern_mcc_perf_core_reset(&APPLE_MODERN_MCC_PERF(dev)->core);
}
static void perf_realize(DeviceState *dev, Error **errp)
{
    AppleModernMCCPerfState *s = APPLE_MODERN_MCC_PERF(dev);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_PERF_VIEWS; i++) {
        s->views[i] = (PerfView){&s->core, i};
        memory_region_init_io(&s->regions[i], OBJECT(dev), &perf_ops, &s->views[i],
            "apple-modern.mcc-perf", i % 2 ? APPLE_MODERN_MCC_PERF_COUNTER_SPAN : 8);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name,
                         void *opaque, Error **errp)
{
    AppleModernMCCPerfState *s = APPLE_MODERN_MCC_PERF(obj);
    uint64_t value = *(uint64_t *)((uint8_t *)&s->core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription perf_unmigratable = {
    .name = TYPE_APPLE_MODERN_MCC_PERF, .unmigratable = 1,
};
static void perf_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = perf_realize;
    dc->vmsd = &perf_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, perf_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCPerfCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCPerfCore, writes));
    object_class_property_add(oc, "event-update-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCPerfCore, event_updates));
}
DeviceState *apple_modern_mcc_perf_new(uint64_t reset_value)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_MCC_PERF);
    APPLE_MODERN_MCC_PERF(dev)->core.reset_value = reset_value;
    apple_modern_mcc_perf_core_reset(&APPLE_MODERN_MCC_PERF(dev)->core);
    return dev;
}
bool apple_modern_mcc_perf_event(DeviceState *dev, unsigned bank,
                                  unsigned counter, uint64_t amount)
{
    return dev && apple_modern_mcc_perf_core_event(&APPLE_MODERN_MCC_PERF(dev)->core,
                                                    bank, counter, amount);
}
static const TypeInfo perf_type = {
    .name = TYPE_APPLE_MODERN_MCC_PERF, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernMCCPerfState), .class_init = perf_class_init,
};
static void perf_register_types(void) { type_register_static(&perf_type); }
type_init(perf_register_types)
#endif
