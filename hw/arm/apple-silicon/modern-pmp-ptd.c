/* PMP PTD message board (Dashboard + Update port) behind an opt-in gate.
 * See the header for what is attested and what is declared.
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
#include "hw/arm/apple-silicon/modern-pmp-ptd.h"

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

static uint64_t little(const uint8_t *p, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static bool scalar(AppleModernBlob tree, const char *name, uint32_t expected,
                   Error **errp)
{
    AppleModernBlob property;
    if (!apple_modern_adt_property(tree, "/arm-io/mcc", name, &property, errp)) {
        return false;
    }
    if (property.size != 4 || little(property.data, 4) != expected) {
        error_setg(errp, "PMP PTD requires matched T8140 %s=%u", name, expected);
        return false;
    }
    return true;
}

bool apple_modern_pmp_ptd_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernPTDPlan *output, Error **errp)
{
    static const uint64_t child[APPLE_MODERN_PTD_VIEWS] = {
        UINT64_C(0xf03c0000), UINT64_C(0xf03d0000)};
    static const uint64_t physical[APPLE_MODERN_PTD_VIEWS] = {
        UINT64_C(0x3003c0000), UINT64_C(0x3003d0000)};
    AppleModernBlob compatible, reg, ranges;
    AppleModernPTDPlan plan = {{0}};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "PMP PTD output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "PMP PTD DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "PMP PTD exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io/mcc", "compatible", &compatible, errp) ||
        !scalar(tree, "pmp_ptd_db_reg_idx", 6, errp) ||
        !scalar(tree, "pmp_ptd_update_reg_idx", 7, errp) ||
        !apple_modern_adt_property(tree, "/arm-io/mcc", "reg", &reg, errp) ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (compatible.size != sizeof("mcc,t8140") ||
        memcmp(compatible.data, "mcc,t8140", sizeof("mcc,t8140")) ||
        reg.size != 12 * 16 || !ranges.size || ranges.size % 24) {
        error_setg(errp, "PMP PTD requires the matched T8140 MCC schema");
        return false;
    }
    for (unsigned view = 0; view < APPLE_MODERN_PTD_VIEWS; view++) {
        unsigned index = 6 + view, matches = 0;
        uint64_t address = physical[view];
        if (little(reg.data + index * 16, 8) != child[view] ||
            little(reg.data + index * 16 + 8, 8) != APPLE_MODERN_PTD_SPAN) {
            error_setg(errp, "PMP PTD reg[%u] geometry disagrees", index);
            return false;
        }
        for (size_t i = 0; i < ranges.size; i += 24) {
            uint64_t c = little(ranges.data + i, 8);
            uint64_t p = little(ranges.data + i + 8, 8);
            uint64_t n = little(ranges.data + i + 16, 8);
            if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
                error_setg(errp, "PMP PTD bus range is empty or wraps");
                return false;
            }
            if (child[view] >= c && child[view] - c <= n &&
                APPLE_MODERN_PTD_SPAN <= n - (child[view] - c)) {
                if (p + (child[view] - c) != address) {
                    error_setg(errp, "PMP PTD bank translation disagrees");
                    return false;
                }
                matches++;
            }
        }
        if (matches != 1 || (address < dram_base + dram_size &&
                             dram_base < address + APPLE_MODERN_PTD_SPAN)) {
            error_setg(errp, "PMP PTD window is ambiguous or overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + APPLE_MODERN_PTD_SPAN) {
                error_setg(errp, "PMP PTD window overlaps another device");
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

void apple_modern_pmp_ptd_core_reset(AppleModernPTDCore *core)
{
    memset(core->msg, 0, sizeof(core->msg));
    memset(core->meta, 0, sizeof(core->meta));
    memset(core->hidden, 0, sizeof(core->hidden));
    core->reads = core->writes = 0;
}

bool apple_modern_pmp_ptd_core_read(AppleModernPTDCore *core, unsigned view,
    uint64_t offset, unsigned size, uint64_t *value)
{
    /* Dashboard only; the Update port is write-only. */
    if (!core || !value || view != APPLE_MODERN_PTD_DASHBOARD || size != 8 ||
        (offset & 7) || offset >= APPLE_MODERN_PTD_SPAN ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    *value = (offset & 8) ? core->meta[offset / 16] : core->msg[offset / 16];
    increment(&core->reads);
    return true;
}

bool apple_modern_pmp_ptd_core_write(AppleModernPTDCore *core, unsigned view,
    uint64_t offset, unsigned size, uint64_t value)
{
    uint64_t slot = offset / 8;
    if (!core || view != APPLE_MODERN_PTD_UPDATE || size != 8 || (offset & 7) ||
        offset >= APPLE_MODERN_PTD_SPAN) {
        return false;
    }
    if (slot < APPLE_MODERN_PTD_ENTRIES) {
        core->msg[slot] = value;
    } else {
        core->hidden[slot - APPLE_MODERN_PTD_ENTRIES] = value;
    }
    increment(&core->writes);
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct PTDView {
    AppleModernPTDCore *core;
    unsigned index;
} PTDView;
struct AppleModernPTDState {
    SysBusDevice parent_obj;
    AppleModernPTDCore core;
    PTDView views[APPLE_MODERN_PTD_VIEWS];
    MemoryRegion regions[APPLE_MODERN_PTD_VIEWS];
};
static MemTxResult ptd_read(void *opaque, hwaddr offset, uint64_t *value,
                            unsigned size, MemTxAttrs attrs)
{
    PTDView *view = opaque;
    return apple_modern_pmp_ptd_core_read(view->core, view->index, offset, size,
                                          value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static MemTxResult ptd_write(void *opaque, hwaddr offset, uint64_t value,
                             unsigned size, MemTxAttrs attrs)
{
    PTDView *view = opaque;
    return apple_modern_pmp_ptd_core_write(view->core, view->index, offset, size,
                                           value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps ptd_ops = {
    .read_with_attrs = ptd_read, .write_with_attrs = ptd_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 8, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 8, .max_access_size = 8},
};
static void ptd_reset(DeviceState *dev)
{
    apple_modern_pmp_ptd_core_reset(&APPLE_MODERN_PMP_PTD(dev)->core);
}
static void ptd_realize(DeviceState *dev, Error **errp)
{
    AppleModernPTDState *s = APPLE_MODERN_PMP_PTD(dev);
    for (unsigned i = 0; i < APPLE_MODERN_PTD_VIEWS; i++) {
        s->views[i] = (PTDView){&s->core, i};
        memory_region_init_io(&s->regions[i], OBJECT(dev), &ptd_ops, &s->views[i],
                              i ? "apple-modern.pmp-ptd-update" :
                                  "apple-modern.pmp-ptd-dashboard",
                              APPLE_MODERN_PTD_SPAN);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernPTDCore *core = &APPLE_MODERN_PMP_PTD(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription ptd_unmigratable = {
    .name = TYPE_APPLE_MODERN_PMP_PTD, .unmigratable = 1,
};
static void ptd_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = ptd_realize;
    dc->vmsd = &ptd_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, ptd_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernPTDCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernPTDCore, writes));
}
DeviceState *apple_modern_pmp_ptd_new(void)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_PMP_PTD);
    ptd_reset(dev);
    return dev;
}
static const TypeInfo ptd_type = {
    .name = TYPE_APPLE_MODERN_PMP_PTD, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernPTDState), .class_init = ptd_class_init,
};
static void register_types(void) { type_register_static(&ptd_type); }
type_init(register_types)
#endif
