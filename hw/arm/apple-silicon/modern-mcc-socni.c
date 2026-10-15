/* Sparse T8140 SOCNI performance channels with a declared virtual profile.
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
#include "hw/arm/apple-silicon/modern-mcc-socni.h"

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
        error_setg(errp, "MCC SOCNI requires matched T8140 %s=%u", name, expected);
        return false;
    }
    return true;
}

unsigned apple_modern_mcc_socni_counter_count(unsigned bank)
{
    static const unsigned counts[] = {31, 36, 35};
    return bank < APPLE_MODERN_MCC_SOCNI_BANKS ? counts[bank] : 0;
}

uint64_t apple_modern_mcc_socni_view_span(unsigned view)
{
    return view < APPLE_MODERN_MCC_SOCNI_VIEWS ?
        (uint64_t)apple_modern_mcc_socni_counter_count(view / 2) *
        (view % 2 ? 8 : 4) : 0;
}

bool apple_modern_mcc_socni_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCSocniPlan *output, Error **errp)
{
    static const uint64_t children[] = {0x3f008000, 0x40008000, 0x41008000};
    static const uint64_t physical[] = {UINT64_C(0x24f008000),
        UINT64_C(0x250008000), UINT64_C(0x251008000)};
    AppleModernBlob compatible, reg, ranges;
    AppleModernMCCSocniPlan plan = {0};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "MCC SOCNI output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "MCC SOCNI DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "MCC SOCNI exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io/mcc", "compatible", &compatible, errp) ||
        !scalar(tree, "socni-reg-idx", 3, errp) ||
        !scalar(tree, "socni-count", 3, errp) ||
        !apple_modern_adt_property(tree, "/arm-io/mcc", "reg", &reg, errp) ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (compatible.size != sizeof("mcc,t8140") ||
        memcmp(compatible.data, "mcc,t8140", sizeof("mcc,t8140")) ||
        reg.size != 12 * 16 || !ranges.size || ranges.size % 24) {
        error_setg(errp, "MCC SOCNI requires the matched T8140 register schema");
        return false;
    }
    /* Validate every range, including ranges not used by these three banks. */
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t c = little(ranges.data + i, 8);
        uint64_t p = little(ranges.data + i + 8, 8);
        uint64_t n = little(ranges.data + i + 16, 8);
        if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
            error_setg(errp, "MCC SOCNI bus range is empty or wraps");
            return false;
        }
    }
    for (unsigned bank = 0; bank < APPLE_MODERN_MCC_SOCNI_BANKS; bank++) {
        if (little(reg.data + (bank + 3) * 16, 8) != children[bank] ||
            little(reg.data + (bank + 3) * 16 + 8, 8) != 0x8000) {
            error_setg(errp, "MCC SOCNI bank %u register tuple disagrees", bank);
            return false;
        }
        unsigned matches = 0;
        for (size_t i = 0; i < ranges.size; i += 24) {
            uint64_t c = little(ranges.data + i, 8);
            uint64_t p = little(ranges.data + i + 8, 8);
            uint64_t n = little(ranges.data + i + 16, 8);
            if (children[bank] >= c && children[bank] - c <= n &&
                0x8000 <= n - (children[bank] - c)) {
                if (p + (children[bank] - c) != physical[bank]) {
                    error_setg(errp, "MCC SOCNI bank %u translation disagrees", bank);
                    return false;
                }
                matches++;
            }
        }
        if (matches != 1) {
            error_setg(errp, "MCC SOCNI bank %u translation missing or ambiguous", bank);
            return false;
        }
        for (unsigned kind = 0; kind < 2; kind++) {
            unsigned view = bank * 2 + kind;
            uint64_t address = physical[bank] +
                (kind ? APPLE_MODERN_MCC_SOCNI_COUNTER_OFFSET : 0);
            uint64_t span = apple_modern_mcc_socni_view_span(view);
            if (address < dram_base + dram_size && dram_base < address + span) {
                error_setg(errp, "MCC SOCNI view overlaps DRAM");
                return false;
            }
            for (size_t i = 0; i < exclusion_count; i++) {
                if (address < exclusions[i].physical_address + exclusions[i].size &&
                    exclusions[i].physical_address < address + span) {
                    error_setg(errp, "MCC SOCNI view overlaps another device");
                    return false;
                }
            }
            plan.addresses[view] = address;
            plan.spans[view] = span;
        }
    }
    *output = plan;
    return true;
}

void apple_modern_mcc_socni_core_reset(AppleModernMCCSocniCore *core)
{
    memset(core->controls, 0, sizeof(core->controls));
    memset(core->values, 0, sizeof(core->values));
    for (unsigned bank = 0; bank < APPLE_MODERN_MCC_SOCNI_BANKS; bank++) {
        for (unsigned index = 0; index < apple_modern_mcc_socni_counter_count(bank); index++) {
            core->values[bank][index] = core->reset_value;
        }
    }
    core->reads = core->writes = core->event_updates = 0;
    core->active_banks = 0;
}

static bool valid_access(unsigned view, uint64_t offset, unsigned size)
{
    unsigned width = view % 2 ? 8 : 4;
    return view < APPLE_MODERN_MCC_SOCNI_VIEWS && size == width &&
           !(offset & (width - 1)) && offset < apple_modern_mcc_socni_view_span(view);
}

bool apple_modern_mcc_socni_core_read(AppleModernMCCSocniCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value)
{
    if (!core || !valid_access(view, offset, size) || !value ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    *value = view % 2 ? core->values[view / 2][offset / 8] :
                       core->controls[view / 2][offset / 4];
    if (core->reads != UINT64_MAX) {
        core->reads++;
    }
    return true;
}

bool apple_modern_mcc_socni_core_write(AppleModernMCCSocniCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value)
{
    /* The current observed subset does not establish counter stores/clears. */
    if (!core || !valid_access(view, offset, size) || view % 2) {
        return false;
    }
    core->controls[view / 2][offset / 4] = (uint32_t)value;
    if (core->writes != UINT64_MAX) {
        core->writes++;
    }
    return true;
}

bool apple_modern_mcc_socni_core_event(AppleModernMCCSocniCore *core,
    unsigned bank, unsigned counter, uint64_t amount)
{
    if (!core || bank >= APPLE_MODERN_MCC_SOCNI_BANKS ||
        counter >= apple_modern_mcc_socni_counter_count(bank)) {
        return false;
    }
    if (amount && (core->controls[bank][counter] & 3) == 3 &&
        (!core->commands_required || (core->active_banks & (1U << bank)))) {
        /* Enable gating and unsigned modulo-64 arithmetic are virtual choices. */
        core->values[bank][counter] += amount;
        if (core->event_updates != UINT64_MAX) {
            core->event_updates++;
        }
    }
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct SocniView {
    AppleModernMCCSocniCore *core;
    unsigned index;
} SocniView;
struct AppleModernMCCSocniState {
    SysBusDevice parent_obj;
    AppleModernMCCSocniCore core;
    SocniView views[APPLE_MODERN_MCC_SOCNI_VIEWS];
    MemoryRegion regions[APPLE_MODERN_MCC_SOCNI_VIEWS];
};
static MemTxResult socni_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    SocniView *view = opaque;
    return apple_modern_mcc_socni_core_read(view->core,
        view->index, offset, size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static MemTxResult socni_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    SocniView *view = opaque;
    return apple_modern_mcc_socni_core_write(view->core,
        view->index, offset, size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps control_ops = {
    .read_with_attrs = socni_read, .write_with_attrs = socni_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};
static const MemoryRegionOps counter_ops = {
    .read_with_attrs = socni_read, .write_with_attrs = socni_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 8, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 8, .max_access_size = 8},
};

static void socni_reset(DeviceState *dev)
{
    apple_modern_mcc_socni_core_reset(&APPLE_MODERN_MCC_SOCNI(dev)->core);
}
static void socni_realize(DeviceState *dev, Error **errp)
{
    AppleModernMCCSocniState *s = APPLE_MODERN_MCC_SOCNI(dev);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SOCNI_VIEWS; i++) {
        s->views[i] = (SocniView){&s->core, i};
        memory_region_init_io(&s->regions[i], OBJECT(dev), i % 2 ? &counter_ops : &control_ops, &s->views[i],
            "apple-modern.mcc-socni", apple_modern_mcc_socni_view_span(i));
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name,
                         void *opaque, Error **errp)
{
    AppleModernMCCSocniState *s = APPLE_MODERN_MCC_SOCNI(obj);
    uint64_t value = *(uint64_t *)((uint8_t *)&s->core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription socni_unmigratable = {
    .name = TYPE_APPLE_MODERN_MCC_SOCNI, .unmigratable = 1,
};
static void socni_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = socni_realize;
    dc->vmsd = &socni_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, socni_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCSocniCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCSocniCore, writes));
    object_class_property_add(oc, "event-update-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernMCCSocniCore, event_updates));
}
DeviceState *apple_modern_mcc_socni_new(uint64_t reset_value)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_MCC_SOCNI);
    APPLE_MODERN_MCC_SOCNI(dev)->core.reset_value = reset_value;
    apple_modern_mcc_socni_core_reset(&APPLE_MODERN_MCC_SOCNI(dev)->core);
    return dev;
}
bool apple_modern_mcc_socni_event(DeviceState *dev, unsigned bank,
                                  unsigned counter, uint64_t amount)
{
    return dev && apple_modern_mcc_socni_core_event(&APPLE_MODERN_MCC_SOCNI(dev)->core,
                                                    bank, counter, amount);
}
AppleModernMCCSocniCore *apple_modern_mcc_socni_attach_commands(DeviceState *dev)
{
    AppleModernMCCSocniCore *core = &APPLE_MODERN_MCC_SOCNI(dev)->core;
    core->commands_required = true;
    core->active_banks = 0;
    return core;
}
static const TypeInfo socni_type = {
    .name = TYPE_APPLE_MODERN_MCC_SOCNI, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernMCCSocniState), .class_init = socni_class_init,
};
static void socni_register_types(void) { type_register_static(&socni_type); }
type_init(socni_register_types)
#endif
