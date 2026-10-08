/*
 * Bounded Apple PMGR power-state cells, selected by the served T8140 ADT.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Schema: AsahiLinux/m1n1 2460b604 src/pmgr.c and proxyclient/m1n1/adt.py.
 * Bit fields: Linux 7b63ef2d drivers/pmdomain/apple/pmgr-pwrstate.c.
 * This is a synchronous power-cell model. It is not the MCC, voltage/DVFS,
 * PMP, interrupt-status or clock-frequency hardware. Unknown registers are
 * explicitly counted and read zero, not made writable register RAM.
 */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#include "qapi/visitor.h"
#include "qemu/module.h"
#include "qemu/log.h"
#include "migration/vmstate.h"
#endif
#include "hw/arm/apple-silicon/modern-pmgr.h"

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
static void error_setg(Error **errp, const char *format, ...)
{
    va_list args;
    if (!errp) {
        return;
    }
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
#endif

static uint64_t get_le(const uint8_t *p, unsigned bytes)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < bytes; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static bool valid_span(uint64_t base, uint64_t size)
{
    return size && size <= UINT64_MAX - base;
}

static bool overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    return a < b + bs && b < a + as;
}

static bool pointer_alias(const void *a, size_t as, const void *b, size_t bs)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return as && bs && (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y ||
                       (x < y + bs && y < x + as));
}

static bool translate(AppleModernBlob ranges, uint64_t offset, uint64_t span,
                      uint64_t *address, Error **errp)
{
    if (!ranges.size || ranges.size % 24 || !valid_span(offset, span)) {
        error_setg(errp, "invalid PMGR bus ranges or register span");
        return false;
    }
    bool found = false;
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t child = get_le(ranges.data + i, 8);
        uint64_t parent = get_le(ranges.data + i + 8, 8);
        uint64_t length = get_le(ranges.data + i + 16, 8);
        if (!valid_span(child, length) || !valid_span(parent, length)) {
            error_setg(errp, "PMGR bus range wraps");
            return false;
        }
        if (offset >= child && offset - child <= length &&
            span <= length - (offset - child)) {
            uint64_t candidate = parent + offset - child;
            if (found && *address != candidate) {
                error_setg(errp, "PMGR bus ranges disagree");
                return false;
            }
            *address = candidate;
            found = true;
        }
    }
    if (!found) {
        error_setg(errp, "PMGR register window is outside arm-io ranges");
    }
    return found;
}

bool apple_modern_pmgr_plan_build(AppleModernBlob dtree,
                                  uint64_t dram_base, uint64_t dram_size,
                                  const AppleModernAddressRange *exclusions,
                                  size_t exclusion_count,
                                  AppleModernPMGRPlan *output, Error **errp)
{
    AppleModernPMGRPlan plan = {0};
    AppleModernBlob reg, groups, devices, ranges, compatible;
    uint32_t group_windows[APPLE_MODERN_PMGR_MAX_WINDOWS];
    uint32_t group_offsets[APPLE_MODERN_PMGR_MAX_WINDOWS];
    uint64_t total = 0;

    if (!output) {
        error_setg(errp, "missing PMGR plan output");
        return false;
    }
    if (pointer_alias(output, sizeof(*output), dtree.data, dtree.size) ||
        exclusion_count > SIZE_MAX / sizeof(*exclusions) ||
        (exclusions && pointer_alias(output, sizeof(*output), exclusions,
                        exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "PMGR plan output aliases its input");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!valid_span(dram_base, dram_size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions)) {
        error_setg(errp, "invalid PMGR DRAM/exclusion spans");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!valid_span(exclusions[i].physical_address, exclusions[i].size)) {
            error_setg(errp, "invalid PMGR register exclusion");
            return false;
        }
    }
    if (!apple_modern_adt_property(dtree, "/arm-io/pmgr", "reg", &reg, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/pmgr", "ps-groups",
                                   &groups, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/pmgr", "devices",
                                   &devices, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (apple_modern_adt_property(dtree, "/arm-io/pmgr", "compatible",
                                  &compatible, NULL) &&
        (compatible.size != sizeof("pmgr1,t8140") ||
         memcmp(compatible.data, "pmgr1,t8140", sizeof("pmgr1,t8140")))) {
        error_setg(errp, "PMGR model only accepts pmgr1,t8140");
        return false;
    }
    /* The strict ADT property reader returns the original unpadded lengths. */
    if (!reg.size || reg.size % 16 || reg.size > 128 * 16 ||
        !groups.size || groups.size % 12 ||
        groups.size > APPLE_MODERN_PMGR_MAX_WINDOWS * 12 ||
        !devices.size || devices.size % 48 ||
        devices.size > APPLE_MODERN_PMGR_MAX_CELLS * 48) {
        error_setg(errp, "unsupported PMGR reg/ps-groups/devices schema");
        return false;
    }
    for (size_t g = 0; g < groups.size / 12; g++) {
        uint32_t index = get_le(groups.data + 12 * g, 4);
        uint32_t offset = get_le(groups.data + 12 * g + 4, 4);
        uint64_t base = 0, span;
        if (index >= reg.size / 16 ||
            get_le(groups.data + 12 * g + 8, 4)) {
            error_setg(errp, "PMGR power-state group index/flags unsupported");
            return false;
        }
        span = get_le(reg.data + 16 * index + 8, 8);
        if (span < 4 || span > APPLE_MODERN_PMGR_MAX_WINDOW ||
            offset > span - 4 || (offset & 3) ||
            !translate(ranges, get_le(reg.data + 16 * index, 8), span,
                        &base, errp)) {
            if (!errp || !*errp) {
                error_setg(errp, "invalid PMGR power-state register window");
            }
            return false;
        }
        unsigned w;
        for (w = 0; w < plan.window_count; w++) {
            if (plan.windows[w].base == base && plan.windows[w].size == span) {
                break;
            }
            if (overlaps(base, span, plan.windows[w].base,
                          plan.windows[w].size)) {
                error_setg(errp, "PMGR power-state windows overlap");
                return false;
            }
        }
        if (w == plan.window_count) {
            if (span > APPLE_MODERN_PMGR_MAX_TOTAL - total ||
                overlaps(base, span, dram_base, dram_size)) {
                error_setg(errp, "PMGR window exceeds budget or overlaps DRAM");
                return false;
            }
            plan.windows[w] = (AppleModernPMGRWindow){base, span};
            total += span;
            plan.window_count++;
        }
        group_windows[g] = w;
        group_offsets[g] = offset;
    }
    for (size_t i = 0; i < devices.size; i += 48) {
        const uint8_t *record = devices.data + i;
        uint32_t offset = get_le(record + 16, 3);
        uint16_t id = get_le(record + 26, 2);
        unsigned group = record[19];
        AppleModernPMGRCell *cell;
        if (!id) {
            error_setg(errp, "PMGR device id must be nonzero");
            return false;
        }
        if (record[0] & 0x10) {
            plan.virtual_count++;
            continue;
        }
        if (group >= groups.size / 12 ||
            offset > UINT32_MAX - group_offsets[group]) {
            error_setg(errp, "PMGR device references an invalid power-state group");
            return false;
        }
        offset += group_offsets[group];
        unsigned window = group_windows[group];
        if ((offset & 7) || plan.windows[window].size < 8 ||
            offset > plan.windows[window].size - 8) {
            error_setg(errp, "PMGR device cell is unaligned or outside its window");
            return false;
        }
        for (size_t j = 0; j < exclusion_count; j++) {
            if (overlaps(plan.windows[window].base + offset, 8,
                          exclusions[j].physical_address, exclusions[j].size)) {
                error_setg(errp, "PMGR power cell overlaps another device");
                return false;
            }
        }
        for (size_t j = 0; j < plan.cell_count; j++) {
            if (plan.cells[j].id == id || (plan.cells[j].window == window &&
                                          plan.cells[j].offset == offset)) {
                error_setg(errp, "duplicate PMGR device id or hardware cell");
                return false;
            }
        }
        cell = &plan.cells[plan.cell_count++];
        *cell = (AppleModernPMGRCell){offset, id, window};
    }
    if (!plan.cell_count) {
        error_setg(errp, "PMGR has no hardware power-state cells");
        return false;
    }
    *output = plan;
    return true;
}

static void increment(uint64_t *counter)
{
    if (*counter != UINT64_MAX) {
        (*counter)++;
    }
}

static int cell_index(const AppleModernPMGRCore *core, unsigned window,
                       uint64_t offset)
{
    if (window >= core->plan.window_count || (offset & 3) ||
        offset >= core->plan.windows[window].size) {
        return -1;
    }
    for (unsigned i = 0; i < core->plan.cell_count; i++) {
        if (core->plan.cells[i].window == window &&
            core->plan.cells[i].offset == offset) {
            return i;
        }
    }
    return -1;
}

void apple_modern_pmgr_core_reset(AppleModernPMGRCore *core)
{
    memset(core->values, 0, sizeof(core->values));
    core->reads = core->writes = 0;
    core->unknown_reads = core->unknown_writes = core->transitions = 0;
}

uint32_t apple_modern_pmgr_core_read(AppleModernPMGRCore *core,
                                    unsigned window, uint64_t offset)
{
    int i = cell_index(core, window, offset);
    increment(&core->reads);
    if (i < 0) {
        increment(&core->unknown_reads);
        return 0;
    }
    return core->values[i];
}

void apple_modern_pmgr_core_write(AppleModernPMGRCore *core,
                                  unsigned window, uint64_t offset,
                                  uint32_t value)
{
    int i = cell_index(core, window, offset);
    increment(&core->writes);
    if (i < 0) {
        increment(&core->unknown_writes);
        return;
    }
    /*
     * Controls: RESET(31), NO_WAKEUP(30), AUTO_ENABLE(28), MIN(19:16),
     * DEV_DISABLE(10), TARGET(3:0).
     *
     * ACTUAL follows TARGET exactly. Every driver that polls this register
     * waits for equality, not for "at least": XNU's _setPSLevel polls mask 0xf0
     * for level << 4, Linux's apple-pmgr-pwrstate.c polls
     * FIELD_GET(APPLE_PMGR_PS_ACTUAL, reg) == pstate, and m1n1's pmgr.c polls
     * PMGR_PS_ACTUAL against FIELD_PREP(..., target_mode). A floor applied to
     * an explicit request would make those polls time out instead of
     * converging. MIN is the floor for AUTOMATIC power management -- the Linux
     * binding reads "Specifies the minimum power state for auto-PM" -- so it is
     * applied only while AUTO_ENABLE is set.
     *
     * NO_WAKEUP is stored rather than dropped. XNU's _enablePSNoWakeup sets it
     * with a read-modify-write, _setPSLevel tests it and clears it, and
     * _setPSLevel's fast path early-returns only when the target already
     * matches AND bits 30 and 10 are both clear (mask 0x40000400). A bit that
     * always read zero therefore changed which branch the driver took.
     *
     * Whether T8140 silicon clamps ACTUAL when AUTO_ENABLE is clear is NOT
     * measured; this follows the three reference drivers' poll contract.
     */
    uint32_t controls = value & UINT32_C(0xd00f040f);
    unsigned target = controls & 15, minimum = (controls >> 16) & 15;
    bool auto_pm = (controls & UINT32_C(0x10000000)) != 0;
    unsigned actual = (auto_pm && minimum > target) ? minimum : target;
    if (((core->values[i] >> 4) & 15) != actual) {
        increment(&core->transitions);
    }
    core->values[i] = controls | (actual << 4);
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct AppleModernPMGRPort {
    AppleModernPMGRState *state;
    unsigned window;
    uint32_t offset;
} AppleModernPMGRPort;

struct AppleModernPMGRState {
    SysBusDevice parent_obj;
    AppleModernPMGRCore core;
    MemoryRegion windows[APPLE_MODERN_PMGR_MAX_WINDOWS];
    MemoryRegion cells[APPLE_MODERN_PMGR_MAX_CELLS];
    AppleModernPMGRPort ports[APPLE_MODERN_PMGR_MAX_CELLS];
};

static uint64_t pmgr_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleModernPMGRPort *port = opaque;
    return apple_modern_pmgr_core_read(&port->state->core, port->window,
                                      port->offset + offset);
}

static void pmgr_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    AppleModernPMGRPort *port = opaque;
    apple_modern_pmgr_core_write(&port->state->core, port->window,
                                 port->offset + offset, value);
}

static const MemoryRegionOps pmgr_ops = {
    .read = pmgr_read,
    .write = pmgr_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 8},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};

static void pmgr_reset(DeviceState *dev)
{
    apple_modern_pmgr_core_reset(&APPLE_MODERN_PMGR(dev)->core);
}

static void pmgr_realize(DeviceState *dev, Error **errp)
{
    AppleModernPMGRState *s = APPLE_MODERN_PMGR(dev);
    if (!s->core.plan.window_count ||
        s->core.plan.window_count > APPLE_MODERN_PMGR_MAX_WINDOWS ||
        !s->core.plan.cell_count ||
        s->core.plan.cell_count > APPLE_MODERN_PMGR_MAX_CELLS) {
        error_setg(errp, "PMGR requires a validated power-state plan");
        return;
    }
    for (unsigned i = 0; i < s->core.plan.window_count; i++) {
        char name[32];
        snprintf(name, sizeof(name), "apple-modern.pmgr%u", i);
        /* Nonterminating container: existing devices in its holes stay live. */
        memory_region_init(&s->windows[i], OBJECT(dev), name,
                           s->core.plan.windows[i].size);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->windows[i]);
    }
    for (unsigned i = 0; i < s->core.plan.cell_count; i++) {
        const AppleModernPMGRCell *cell = &s->core.plan.cells[i];
        char name[32];
        snprintf(name, sizeof(name), "apple-modern.pmgr-cell-%x", cell->id);
        s->ports[i] = (AppleModernPMGRPort){s, cell->window, cell->offset};
        memory_region_init_io(&s->cells[i], OBJECT(dev), &pmgr_ops,
                              &s->ports[i], name, 8);
        memory_region_add_subregion(&s->windows[cell->window], cell->offset,
                                     &s->cells[i]);
    }
    apple_modern_pmgr_core_reset(&s->core);
}

static void get_counter(Object *obj, Visitor *v, const char *name,
                         void *opaque, Error **errp)
{
    AppleModernPMGRState *s = APPLE_MODERN_PMGR(obj);
    uint64_t value = *(uint64_t *)((uint8_t *)&s->core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}

static const VMStateDescription vmstate_unmigratable = {
    .name = TYPE_APPLE_MODERN_PMGR,
    .unmigratable = 1,
};

static void pmgr_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = pmgr_realize;
    dc->vmsd = &vmstate_unmigratable;
    device_class_set_legacy_reset(dc, pmgr_reset);
#define COUNTER(n, f) object_class_property_add(oc, n, "uint64", \
    get_counter, NULL, NULL, (void *)offsetof(AppleModernPMGRCore, f))
    COUNTER("mmio-read-count", reads);
    COUNTER("mmio-write-count", writes);
    COUNTER("unknown-read-count", unknown_reads);
    COUNTER("unknown-write-count", unknown_writes);
    COUNTER("power-transition-count", transitions);
#undef COUNTER
}

DeviceState *apple_modern_pmgr_new(const AppleModernPMGRPlan *plan)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_PMGR);
    APPLE_MODERN_PMGR(dev)->core.plan = *plan;
    return dev;
}

static const TypeInfo pmgr_info = {
    .name = TYPE_APPLE_MODERN_PMGR,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernPMGRState),
    .class_init = pmgr_class_init,
};

static void pmgr_register_types(void)
{
    type_register_static(&pmgr_info);
}
type_init(pmgr_register_types)
#endif
