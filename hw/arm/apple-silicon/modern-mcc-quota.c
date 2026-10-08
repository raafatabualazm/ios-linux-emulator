/* Sparse ordinary T8140 DSID quota storage, with declared virtual broadcast.
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
#include "hw/arm/apple-silicon/modern-mcc-quota.h"

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
        error_setg(errp, "MCC quota requires matched T8140 %s=%u", name, expected);
        return false;
    }
    return true;
}

bool apple_modern_mcc_quota_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCQuotaPlan *output, Error **errp)
{
    AppleModernBlob compatible, reg, ranges;
    AppleModernMCCQuotaPlan plan = {0};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "MCC quota output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "MCC quota DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "MCC quota exclusion is empty or wraps");
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
        error_setg(errp, "MCC quota requires the matched T8140 AMCC schema");
        return false;
    }
    unsigned matches = 0;
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t c = little(ranges.data + i, 8);
        uint64_t p = little(ranges.data + i + 8, 8);
        uint64_t n = little(ranges.data + i + 16, 8);
        if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
            error_setg(errp, "MCC quota bus range is empty or wraps");
            return false;
        }
        if (UINT64_C(0x10000000) >= c && UINT64_C(0x10000000) - c <= n &&
            0x140000 <= n - (UINT64_C(0x10000000) - c)) {
            if (p + (UINT64_C(0x10000000) - c) != UINT64_C(0x220000000)) {
                error_setg(errp, "MCC quota AMCC translation disagrees");
                return false;
            }
            matches++;
        }
    }
    if (matches != 1) {
        error_setg(errp, "MCC quota AMCC translation is missing or ambiguous");
        return false;
    }
    for (unsigned view = 0; view < APPLE_MODERN_MCC_QUOTA_VIEWS; view++) {
        uint64_t address = UINT64_C(0x220000000) +
            (uint64_t)view * APPLE_MODERN_MCC_QUOTA_PLANE_STRIDE +
            APPLE_MODERN_MCC_QUOTA_OFFSET;
        if (address < dram_base + dram_size &&
            dram_base < address + APPLE_MODERN_MCC_QUOTA_SPAN) {
            error_setg(errp, "MCC quota bank overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + APPLE_MODERN_MCC_QUOTA_SPAN) {
                error_setg(errp, "MCC quota bank overlaps another device");
                return false;
            }
        }
        plan.addresses[view] = address;
    }
    *output = plan;
    return true;
}

void apple_modern_mcc_quota_core_reset(AppleModernMCCQuotaCore *core)
{
    for (unsigned plane = 0; plane < APPLE_MODERN_MCC_QUOTA_PLANES; plane++) {
        for (unsigned group = 0; group < APPLE_MODERN_MCC_QUOTA_GROUPS; group++) {
            core->values[plane][group] = core->reset_value;
        }
    }
    core->reads = core->writes = core->broadcast_writes = 0;
}

static bool valid_offset(uint64_t offset)
{
    return offset < APPLE_MODERN_MCC_QUOTA_SPAN && !(offset & 3);
}

bool apple_modern_mcc_quota_core_read(AppleModernMCCQuotaCore *core,
    unsigned view, uint64_t offset, uint32_t *value)
{
    /* Only the observed plane read view is implemented. */
    if (!core || view >= APPLE_MODERN_MCC_QUOTA_PLANES ||
        !valid_offset(offset) || !value ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    *value = core->values[view][offset / 4];
    if (core->reads != UINT64_MAX) {
        core->reads++;
    }
    return true;
}

bool apple_modern_mcc_quota_core_write(AppleModernMCCQuotaCore *core,
    unsigned view, uint64_t offset, uint32_t value)
{
    if (!core || view >= APPLE_MODERN_MCC_QUOTA_VIEWS || !valid_offset(offset)) {
        return false;
    }
    if (view == APPLE_MODERN_MCC_QUOTA_GLOBAL) {
        /* Declared virtual broadcast inference from paired driver accessors. */
        for (unsigned plane = 0; plane < APPLE_MODERN_MCC_QUOTA_PLANES; plane++) {
            core->values[plane][offset / 4] = value;
        }
        if (core->broadcast_writes != UINT64_MAX) {
            core->broadcast_writes++;
        }
    } else {
        core->values[view][offset / 4] = value;
    }
    if (core->writes != UINT64_MAX) {
        core->writes++;
    }
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct QuotaView {
    AppleModernMCCQuotaCore *core;
    unsigned index;
} QuotaView;
struct AppleModernMCCQuotaState {
    SysBusDevice parent_obj;
    AppleModernMCCQuotaCore core;
    QuotaView views[APPLE_MODERN_MCC_QUOTA_VIEWS];
    MemoryRegion banks[APPLE_MODERN_MCC_QUOTA_VIEWS];
};
static MemTxResult quota_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    QuotaView *view = opaque;
    uint32_t word;
    if (size != 4 || !apple_modern_mcc_quota_core_read(view->core,
                                                     view->index, offset, &word)) {
        return MEMTX_ACCESS_ERROR;
    }
    *value = word;
    return MEMTX_OK;
}
static MemTxResult quota_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    QuotaView *view = opaque;
    return size == 4 && apple_modern_mcc_quota_core_write(view->core,
        view->index, offset, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps quota_ops = {
    .read_with_attrs = quota_read, .write_with_attrs = quota_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};
static void quota_reset(DeviceState *dev)
{
    apple_modern_mcc_quota_core_reset(&APPLE_MODERN_MCC_QUOTA(dev)->core);
}
static void quota_realize(DeviceState *dev, Error **errp)
{
    AppleModernMCCQuotaState *s = APPLE_MODERN_MCC_QUOTA(dev);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_QUOTA_VIEWS; i++) {
        s->views[i] = (QuotaView){&s->core, i};
        memory_region_init_io(&s->banks[i], OBJECT(dev), &quota_ops, &s->views[i],
                               "apple-modern.mcc-quota", APPLE_MODERN_MCC_QUOTA_SPAN);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->banks[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name,
                         void *opaque, Error **errp)
{
    AppleModernMCCQuotaState *s = APPLE_MODERN_MCC_QUOTA(obj);
    uint64_t value = *(uint64_t *)((uint8_t *)&s->core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription quota_unmigratable = {
    .name = TYPE_APPLE_MODERN_MCC_QUOTA, .unmigratable = 1,
};
static void quota_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = quota_realize;
    dc->vmsd = &quota_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, quota_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCQuotaCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCQuotaCore, writes));
    object_class_property_add(oc, "broadcast-write-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCQuotaCore, broadcast_writes));
}
DeviceState *apple_modern_mcc_quota_new(uint32_t reset_value)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_MCC_QUOTA);
    APPLE_MODERN_MCC_QUOTA(dev)->core.reset_value = reset_value;
    apple_modern_mcc_quota_core_reset(&APPLE_MODERN_MCC_QUOTA(dev)->core);
    return dev;
}
static const TypeInfo quota_type = {
    .name = TYPE_APPLE_MODERN_MCC_QUOTA, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernMCCQuotaState), .class_init = quota_class_init,
};
static void quota_register_types(void) { type_register_static(&quota_type); }
type_init(quota_register_types)
#endif
