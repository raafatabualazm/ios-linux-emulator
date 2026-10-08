/* Immutable, explicitly supplied T8140 PMGR_AON_FUSE input.
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
#include "migration/vmstate.h"
#endif
#include "hw/arm/apple-silicon/modern-pmgr-fuse.h"

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

static uint64_t little(const uint8_t *bytes, unsigned count)
{
    uint64_t result = 0;
    for (unsigned i = 0; i < count; i++) {
        result |= (uint64_t)bytes[i] << (8 * i);
    }
    return result;
}

static bool aliases(const void *a, size_t as, const void *b, size_t bs)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return as && bs && (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y ||
                       (x < y + bs && y < x + as));
}

static bool overlap(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    return a < b + bs && b < a + as;
}

bool apple_modern_pmgr_fuse_plan_build(AppleModernBlob dtree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernPMGRFusePlan *output, Error **errp)
{
    AppleModernPMGRPlan power;
    AppleModernBlob reg, ranges;
    const uint64_t base = APPLE_MODERN_PMGR_FUSE_BASE;
    const uint64_t size = APPLE_MODERN_PMGR_FUSE_SIZE;
    bool translated = false;
    if (!output || aliases(output, sizeof(*output), dtree.data, dtree.size) ||
        exclusion_count > SIZE_MAX / sizeof(*exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "PMGR fuse plan output is missing or aliases input");
        return false;
    }
    memset(output, 0, sizeof(*output));
    /* Reuse the strict matched schema and external span validation. */
    if (!apple_modern_pmgr_plan_build(dtree, dram_base, dram_size, exclusions,
                                      exclusion_count, &power, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io/pmgr", "reg", &reg, errp) ||
        !apple_modern_adt_property(dtree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (reg.size != 44 * 16 || little(reg.data + 30 * 16, 8) != 0xf82c8000 ||
        little(reg.data + 30 * 16 + 8, 8) != size ||
        !ranges.size || ranges.size % 24) {
        error_setg(errp, "PMGR fuse bank requires the matched T8140 reg[30]");
        return false;
    }
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t child = little(ranges.data + i, 8);
        uint64_t parent = little(ranges.data + i + 8, 8);
        uint64_t length = little(ranges.data + i + 16, 8);
        uint64_t target = UINT64_C(0xf82c8000);
        if (!length || length > UINT64_MAX - child ||
            length > UINT64_MAX - parent) {
            error_setg(errp, "PMGR fuse bus range wraps");
            return false;
        }
        if (target >= child && target - child <= length &&
            size <= length - (target - child)) {
            if (parent + target - child != base) {
                error_setg(errp, "PMGR fuse physical translation disagrees");
                return false;
            }
            translated = true;
        }
    }
    if (!translated || overlap(base, size, dram_base, dram_size)) {
        error_setg(errp, "PMGR fuse bank is untranslatable or overlaps DRAM");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (overlap(base, size, exclusions[i].physical_address,
                     exclusions[i].size)) {
            error_setg(errp, "PMGR fuse bank overlaps another device");
            return false;
        }
    }
    for (unsigned i = 0; i < power.cell_count; i++) {
        const AppleModernPMGRCell *cell = &power.cells[i];
        if (overlap(base, size, power.windows[cell->window].base + cell->offset, 8)) {
            error_setg(errp, "PMGR fuse bank overlaps a power-state cell");
            return false;
        }
    }
    *output = (AppleModernPMGRFusePlan){base, size};
    return true;
}

void apple_modern_pmgr_fuse_core_reset(AppleModernPMGRFuseCore *core)
{
    core->reads = core->rejected_writes = 0;
}

bool apple_modern_pmgr_fuse_core_load(AppleModernPMGRFuseCore *core,
                                      AppleModernBlob image, Error **errp)
{
    if (!core || !image.data || image.size != APPLE_MODERN_PMGR_FUSE_SIZE ||
        aliases(core, sizeof(*core), image.data, image.size)) {
        error_setg(errp, "PMGR fuse input must be a disjoint exact 0x4000-byte image");
        return false;
    }
    memcpy(core->image, image.data, image.size);
    core->loaded = true;
    apple_modern_pmgr_fuse_core_reset(core);
    return true;
}

bool apple_modern_pmgr_fuse_core_read(AppleModernPMGRFuseCore *core,
                                      uint64_t offset, uint32_t *value)
{
    if (!core || !core->loaded || !value || (offset & 3) ||
        offset > APPLE_MODERN_PMGR_FUSE_SIZE - 4 ||
        aliases(value, sizeof(*value), core, sizeof(*core))) {
        return false;
    }
    *value = little(core->image + offset, 4);
    if (core->reads != UINT64_MAX) {
        core->reads++;
    }
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
struct AppleModernPMGRFuseState {
    SysBusDevice parent_obj;
    AppleModernPMGRFuseCore core;
    MemoryRegion mmio;
};

static MemTxResult fuse_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    uint32_t word;
    if (size != 4 || !apple_modern_pmgr_fuse_core_read(
            &APPLE_MODERN_PMGR_FUSE(opaque)->core, offset, &word)) {
        return MEMTX_ACCESS_ERROR;
    }
    *value = word;
    return MEMTX_OK;
}

static MemTxResult fuse_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    AppleModernPMGRFuseCore *core = &APPLE_MODERN_PMGR_FUSE(opaque)->core;
    if (core->rejected_writes != UINT64_MAX) {
        core->rejected_writes++;
    }
    /* Factory programming is unsupported; no value is silently accepted. */
    return MEMTX_ACCESS_ERROR;
}

static const MemoryRegionOps fuse_ops = {
    .read_with_attrs = fuse_read,
    .write_with_attrs = fuse_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};

static void fuse_reset(DeviceState *dev)
{
    apple_modern_pmgr_fuse_core_reset(&APPLE_MODERN_PMGR_FUSE(dev)->core);
}

static void fuse_realize(DeviceState *dev, Error **errp)
{
    AppleModernPMGRFuseState *s = APPLE_MODERN_PMGR_FUSE(dev);
    if (!s->core.loaded) {
        error_setg(errp, "PMGR fuse device needs an explicit immutable input");
        return;
    }
    memory_region_init_io(&s->mmio, OBJECT(dev), &fuse_ops, s,
                           "apple-modern.pmgr-aon-fuse", APPLE_MODERN_PMGR_FUSE_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
}

static void get_counter(Object *obj, Visitor *v, const char *name,
                         void *opaque, Error **errp)
{
    AppleModernPMGRFuseState *s = APPLE_MODERN_PMGR_FUSE(obj);
    uint64_t value = *(uint64_t *)((uint8_t *)&s->core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}

static const VMStateDescription fuse_unmigratable = {
    .name = TYPE_APPLE_MODERN_PMGR_FUSE,
    .unmigratable = 1,
};

static void fuse_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = fuse_realize;
    dc->vmsd = &fuse_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, fuse_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernPMGRFuseCore, reads));
    object_class_property_add(oc, "rejected-write-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernPMGRFuseCore, rejected_writes));
}

DeviceState *apple_modern_pmgr_fuse_new(AppleModernBlob image, Error **errp)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_PMGR_FUSE);
    if (!apple_modern_pmgr_fuse_core_load(&APPLE_MODERN_PMGR_FUSE(dev)->core,
                                         image, errp)) {
        object_unref(OBJECT(dev));
        return NULL;
    }
    return dev;
}

static const TypeInfo fuse_info = {
    .name = TYPE_APPLE_MODERN_PMGR_FUSE,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernPMGRFuseState),
    .class_init = fuse_class_init,
};
static void register_types(void)
{
    type_register_static(&fuse_info);
}
type_init(register_types)
#endif
