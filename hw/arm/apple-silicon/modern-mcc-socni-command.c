/* Sparse T8140 SOCNI counter-bank activation with a declared virtual profile.
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
#include "hw/qdev-properties.h"
#endif
#include "hw/arm/apple-silicon/modern-mcc-socni-command.h"

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

bool apple_modern_mcc_socni_command_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernMCCSocniCommandPlan *output, Error **errp)
{
    AppleModernMCCSocniPlan geometry;
    AppleModernMCCSocniCommandPlan plan = {0};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "SOCNI command output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "SOCNI command exclusion is empty or wraps");
            return false;
        }
    }
    /* Reuse matched tuple/range validation without supplying the already
     * mapped control/counter views as exclusions of their own geometry. */
    if (!apple_modern_mcc_socni_plan_build(tree, dram_base, dram_size,
                                          NULL, 0, &geometry, errp)) {
        return false;
    }
    for (unsigned view = 0; view < APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS; view++) {
        uint64_t address = geometry.addresses[view * 2] +
            APPLE_MODERN_MCC_SOCNI_COMMAND_OFFSET;
        uint64_t span = APPLE_MODERN_MCC_SOCNI_COMMAND_SPAN;
        if (address < dram_base + dram_size && dram_base < address + span) {
            error_setg(errp, "SOCNI command view overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + span) {
                error_setg(errp, "SOCNI command view overlaps another device");
                return false;
            }
        }
        plan.addresses[view] = address;
    }
    *output = plan;
    return true;
}

void apple_modern_mcc_socni_command_core_reset(AppleModernMCCSocniCommandCore *core)
{
    AppleModernMCCSocniCore *channels = core->channels;
    memset(core, 0, sizeof(*core));
    core->channels = channels;
    if (channels) {
        channels->active_banks = 0;
    }
}

bool apple_modern_mcc_socni_command_core_read(AppleModernMCCSocniCommandCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t *value)
{
    /* No command readback contract has been established. */
    (void)core;
    (void)view;
    (void)offset;
    (void)size;
    (void)value;
    return false;
}

bool apple_modern_mcc_socni_command_core_write(AppleModernMCCSocniCommandCore *core,
    unsigned view, uint64_t offset, unsigned size, uint64_t value)
{
    if (!core || !core->channels || !core->channels->commands_required ||
        view >= APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS || offset ||
        size != 4 || value != APPLE_MODERN_MCC_SOCNI_COMMAND_RESTORE) {
        return false;
    }
    /* XNU writes 1 at bank+0x100 after restoring an enabled channel.
     * Model that request as enabling bank event collection. Sampling and
     * disabling still use the existing per-channel register controls.
     * Clearing counters here would destroy other enabled channels' samples;
     * no observed driver contract establishes such a clear. */
    core->channels->active_banks |= 1U << view;
    if (core->writes != UINT64_MAX) {
        core->writes++;
    }
    if (core->requests[view] != UINT64_MAX) {
        core->requests[view]++;
    }
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct CommandView {
    AppleModernMCCSocniCommandCore *core;
    unsigned index;
} CommandView;
struct AppleModernMCCSocniCommandState {
    SysBusDevice parent_obj;
    DeviceState *channels;
    AppleModernMCCSocniCommandCore core;
    CommandView views[APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS];
    MemoryRegion regions[APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS];
};
static MemTxResult command_read(void *opaque, hwaddr offset, uint64_t *value,
                               unsigned size, MemTxAttrs attrs)
{
    CommandView *view = opaque;
    return apple_modern_mcc_socni_command_core_read(view->core,
        view->index, offset, size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static MemTxResult command_write(void *opaque, hwaddr offset, uint64_t value,
                                unsigned size, MemTxAttrs attrs)
{
    CommandView *view = opaque;
    return apple_modern_mcc_socni_command_core_write(view->core,
        view->index, offset, size, value) ? MEMTX_OK : MEMTX_ACCESS_ERROR;
}
static const MemoryRegionOps command_ops = {
    .read_with_attrs = command_read, .write_with_attrs = command_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};
static void command_reset(DeviceState *dev)
{
    apple_modern_mcc_socni_command_core_reset(&APPLE_MODERN_MCC_SOCNI_COMMAND(dev)->core);
}
static void command_realize(DeviceState *dev, Error **errp)
{
    AppleModernMCCSocniCommandState *s = APPLE_MODERN_MCC_SOCNI_COMMAND(dev);
    if (!s->channels) {
        error_setg(errp, "SOCNI commands require a counter-bank device");
        return;
    }
    s->core.channels = apple_modern_mcc_socni_attach_commands(s->channels);
    for (unsigned i = 0; i < APPLE_MODERN_MCC_SOCNI_COMMAND_VIEWS; i++) {
        s->views[i] = (CommandView){&s->core, i};
        memory_region_init_io(&s->regions[i], OBJECT(dev), &command_ops, &s->views[i],
            "apple-modern.mcc-socni-command", APPLE_MODERN_MCC_SOCNI_COMMAND_SPAN);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_writes(Object *obj, Visitor *v, const char *name,
                       void *opaque, Error **errp)
{
    uint64_t value = APPLE_MODERN_MCC_SOCNI_COMMAND(obj)->core.writes;
    visit_type_uint64(v, name, &value, errp);
}
static void get_active(Object *obj, Visitor *v, const char *name,
                       void *opaque, Error **errp)
{
    AppleModernMCCSocniCommandState *s = APPLE_MODERN_MCC_SOCNI_COMMAND(obj);
    uint32_t value = s->core.channels ? s->core.channels->active_banks : 0;
    visit_type_uint32(v, name, &value, errp);
}
static const Property command_properties[] = {
    DEFINE_PROP_LINK("channels", AppleModernMCCSocniCommandState, channels,
                     TYPE_APPLE_MODERN_MCC_SOCNI, DeviceState *),
};
static const VMStateDescription command_unmigratable = {
    .name = TYPE_APPLE_MODERN_MCC_SOCNI_COMMAND, .unmigratable = 1,
};
static void command_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = command_realize;
    dc->vmsd = &command_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, command_reset);
    device_class_set_props(dc, command_properties);
    object_class_property_add(oc, "command-write-count", "uint64", get_writes,
                               NULL, NULL, NULL);
    object_class_property_add(oc, "active-bank-mask", "uint32", get_active,
                               NULL, NULL, NULL);
}
DeviceState *apple_modern_mcc_socni_command_new(DeviceState *channels)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_MCC_SOCNI_COMMAND);
    object_property_set_link(OBJECT(dev), "channels", OBJECT(channels), &error_abort);
    apple_modern_mcc_socni_command_core_reset(&APPLE_MODERN_MCC_SOCNI_COMMAND(dev)->core);
    return dev;
}
static const TypeInfo command_type = {
    .name = TYPE_APPLE_MODERN_MCC_SOCNI_COMMAND, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernMCCSocniCommandState), .class_init = command_class_init,
};
static void command_register_types(void) { type_register_static(&command_type); }
type_init(command_register_types)
#endif
