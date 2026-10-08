/* Sparse T8140 DCS DRAM configuration words; no cache/protection apertures.
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
#include "hw/arm/apple-silicon/modern-mcc-dramcfg.h"

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
        error_setg(errp, "MCC DRAMCFG requires matched T8140 %s=%u", name, expected);
        return false;
    }
    return true;
}

bool apple_modern_mcc_dramcfg_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCDRAMCFGPlan *output, Error **errp)
{
    AppleModernBlob compatible, reg, ranges;
    AppleModernMCCDRAMCFGPlan plan = {0};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "MCC DRAMCFG output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "MCC DRAMCFG DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "MCC DRAMCFG exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io/mcc", "compatible", &compatible, errp) ||
        !scalar(tree, "dcs-reg-idx", 8, errp) ||
        !scalar(tree, "dcs-count-per-amcc", 4, errp) ||
        !scalar(tree, "amcc-count", 1, errp) ||
        !apple_modern_adt_property(tree, "/arm-io/mcc", "reg", &reg, errp) ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (compatible.size != sizeof("mcc,t8140") ||
        memcmp(compatible.data, "mcc,t8140", sizeof("mcc,t8140")) ||
        reg.size != 12 * 16 || !ranges.size || ranges.size % 24) {
        error_setg(errp, "MCC DRAMCFG requires the matched T8140 DCS schema");
        return false;
    }
    for (unsigned bank = 0; bank < APPLE_MODERN_MCC_DCS_COUNT; bank++) {
        uint64_t child = little(reg.data + (8 + bank) * 16, 8);
        uint64_t span = little(reg.data + (8 + bank) * 16 + 8, 8);
        uint64_t expected = UINT64_C(0x220400000) + (uint64_t)bank * 0x200000;
        unsigned matches = 0;
        if (child != UINT64_C(0x10400000) + (uint64_t)bank * 0x200000 ||
            span != 0x8000) {
            error_setg(errp, "MCC DRAMCFG DCS bank %u geometry disagrees", bank);
            return false;
        }
        for (size_t i = 0; i < ranges.size; i += 24) {
            uint64_t c = little(ranges.data + i, 8);
            uint64_t p = little(ranges.data + i + 8, 8);
            uint64_t n = little(ranges.data + i + 16, 8);
            if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
                error_setg(errp, "MCC DRAMCFG bus range is empty or wraps");
                return false;
            }
            if (child >= c && child - c <= n && span <= n - (child - c)) {
                if (p + (child - c) != expected) {
                    error_setg(errp, "MCC DRAMCFG bank translation disagrees");
                    return false;
                }
                matches++;
            }
        }
        uint64_t address = expected + APPLE_MODERN_MCC_DRAMCFG_OFFSET;
        if (matches != 1 || (address < dram_base + dram_size &&
                             dram_base < address + 4)) {
            error_setg(errp, "MCC DRAMCFG bank is ambiguous or overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + 4) {
                error_setg(errp, "MCC DRAMCFG word overlaps another device");
                return false;
            }
        }
        plan.addresses[bank] = address;
    }
    *output = plan;
    return true;
}

void apple_modern_mcc_dramcfg_core_reset(AppleModernMCCDRAMCFGCore *core)
{
    for (unsigned i = 0; i < APPLE_MODERN_MCC_DCS_COUNT; i++) {
        core->values[i] = core->reset_value;
    }
    core->reads = core->writes = 0;
}

bool apple_modern_mcc_dramcfg_core_read(AppleModernMCCDRAMCFGCore *core,
    unsigned bank, uint64_t offset, uint32_t *value)
{
    if (!core || bank >= APPLE_MODERN_MCC_DCS_COUNT || offset || !value ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    *value = core->values[bank];
    if (core->reads != UINT64_MAX) {
        core->reads++;
    }
    return true;
}

bool apple_modern_mcc_dramcfg_core_write(AppleModernMCCDRAMCFGCore *core,
    unsigned bank, uint64_t offset, uint32_t value)
{
    if (!core || bank >= APPLE_MODERN_MCC_DCS_COUNT || offset) {
        return false;
    }
    core->values[bank] = value;
    if (core->writes != UINT64_MAX) {
        core->writes++;
    }
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct DRAMCFGBank {
    AppleModernMCCDRAMCFGCore *core;
    unsigned index;
} DRAMCFGBank;
struct AppleModernMCCDRAMCFGState {
    SysBusDevice parent_obj;
    AppleModernMCCDRAMCFGCore core;
    DRAMCFGBank banks[APPLE_MODERN_MCC_DCS_COUNT];
    MemoryRegion words[APPLE_MODERN_MCC_DCS_COUNT];
};

static MemTxResult cfg_read(void *opaque, hwaddr offset, uint64_t *value,
                            unsigned size, MemTxAttrs attrs)
{
    DRAMCFGBank *bank = opaque;
    uint32_t word;
    if (size != 4 || !apple_modern_mcc_dramcfg_core_read(bank->core,
                                                       bank->index, offset, &word)) {
        return MEMTX_ACCESS_ERROR;
    }
    *value = word;
    return MEMTX_OK;
}
static MemTxResult cfg_write(void *opaque, hwaddr offset, uint64_t value,
                             unsigned size, MemTxAttrs attrs)
{
    DRAMCFGBank *bank = opaque;
    return size == 4 && apple_modern_mcc_dramcfg_core_write(bank->core,
        bank->index, offset, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps cfg_ops = {
    .read_with_attrs = cfg_read, .write_with_attrs = cfg_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};
static void cfg_reset(DeviceState *dev)
{
    apple_modern_mcc_dramcfg_core_reset(&APPLE_MODERN_MCC_DRAMCFG(dev)->core);
}
static void cfg_realize(DeviceState *dev, Error **errp)
{
    AppleModernMCCDRAMCFGState *s = APPLE_MODERN_MCC_DRAMCFG(dev);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_DCS_COUNT; i++) {
        s->banks[i] = (DRAMCFGBank){&s->core, i};
        memory_region_init_io(&s->words[i], OBJECT(dev), &cfg_ops, &s->banks[i],
                               "apple-modern.mcc-dramcfg", 4);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->words[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name,
                         void *opaque, Error **errp)
{
    AppleModernMCCDRAMCFGState *s = APPLE_MODERN_MCC_DRAMCFG(obj);
    uint64_t value = *(uint64_t *)((uint8_t *)&s->core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription cfg_unmigratable = {
    .name = TYPE_APPLE_MODERN_MCC_DRAMCFG, .unmigratable = 1,
};
static void cfg_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = cfg_realize;
    dc->vmsd = &cfg_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, cfg_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCDRAMCFGCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCDRAMCFGCore, writes));
}
DeviceState *apple_modern_mcc_dramcfg_new(uint32_t reset_value)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_MCC_DRAMCFG);
    APPLE_MODERN_MCC_DRAMCFG(dev)->core.reset_value = reset_value;
    apple_modern_mcc_dramcfg_core_reset(&APPLE_MODERN_MCC_DRAMCFG(dev)->core);
    return dev;
}
static const TypeInfo cfg_type = {
    .name = TYPE_APPLE_MODERN_MCC_DRAMCFG, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernMCCDRAMCFGState), .class_init = cfg_class_init,
};
static void cfg_register_types(void) { type_register_static(&cfg_type); }
type_init(cfg_register_types)
#endif
