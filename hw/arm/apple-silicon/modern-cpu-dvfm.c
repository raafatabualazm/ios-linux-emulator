/* CPU cluster DVFM state-table windows (declared zero-reset storage).
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
#include "qemu/error-report.h"
#include "migration/vmstate.h"
#endif
#include "hw/arm/apple-silicon/modern-cpu-dvfm.h"

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

bool apple_modern_cpu_dvfm_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDVFMPlan *output, Error **errp)
{
    /* 0/1: state tables at +0xe78000; 2/3: DVFM control page (RegMap
     * E_ACC_CPM_DVFM / P_ACC0_CPM_DVFM) at +0xe70000 of the same clusters. */
    static const uint64_t physical[APPLE_MODERN_DVFM_WINDOWS] = {
        UINT64_C(0x210e78000), UINT64_C(0x211e78000),
        UINT64_C(0x210e70000), UINT64_C(0x211e70000)};
    static const char *const cpus[APPLE_MODERN_DVFM_WINDOWS] = {
        "/cpus/cpu0", "/cpus/cpu4", "/cpus/cpu0", "/cpus/cpu4"};
    AppleModernBlob ranges, impl;
    AppleModernDVFMPlan plan = {{0}};
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "CPU DVFM output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "CPU DVFM DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "CPU DVFM exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp) ||
        !ranges.size || ranges.size % 24) {
        if (errp && !*errp) {
            error_setg(errp, "CPU DVFM requires /arm-io ranges");
        }
        return false;
    }
    for (unsigned w = 0; w < APPLE_MODERN_DVFM_WINDOWS; w++) {
        unsigned matches = 0;
        uint64_t address = physical[w];
        /* The cluster's cpu-impl-reg anchors the cluster stride: the window
         * must lie in the same 16 MiB cluster page-table as that register. */
        if (!apple_modern_adt_property(tree, cpus[w], "cpu-impl-reg", &impl, errp)) {
            return false;
        }
        if (impl.size != 16 || (little(impl.data, 8) >> 24) != (address >> 24)) {
            error_setg(errp, "CPU DVFM window %u is not in cluster of %s", w, cpus[w]);
            return false;
        }
        for (size_t i = 0; i < ranges.size; i += 24) {
            uint64_t c = little(ranges.data + i, 8);
            uint64_t p = little(ranges.data + i + 8, 8);
            uint64_t n = little(ranges.data + i + 16, 8);
            if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
                error_setg(errp, "CPU DVFM bus range is empty or wraps");
                return false;
            }
            if (address >= p && address - p <= n &&
                APPLE_MODERN_DVFM_SPAN <= n - (address - p)) {
                matches++;
            }
        }
        if (matches != 1 || (address < dram_base + dram_size &&
                             dram_base < address + APPLE_MODERN_DVFM_SPAN)) {
            error_setg(errp, "CPU DVFM window is outside arm-io, ambiguous or overlaps DRAM");
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (address < exclusions[i].physical_address + exclusions[i].size &&
                exclusions[i].physical_address < address + APPLE_MODERN_DVFM_SPAN) {
                error_setg(errp, "CPU DVFM window overlaps another device");
                return false;
            }
        }
        plan.addresses[w] = address;
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

void apple_modern_cpu_dvfm_core_reset(AppleModernDVFMCore *core)
{
    memset(core->words, 0, sizeof(core->words));
    memset(core->touched, 0, sizeof(core->touched));
    core->reads = core->writes = 0;
}

/* The only control-page registers the BootKC reads (descriptor tables at
 * 0xfffffff0081a9490 for E and 0xfffffff0081a94b0 for P), as 64-bit loads. */
static bool control_register(unsigned window, uint64_t offset)
{
    switch (window) {
    case APPLE_MODERN_DVFM_TABLE_WINDOWS:
        return offset == 0xa8 || offset == 0xd0;
    case APPLE_MODERN_DVFM_TABLE_WINDOWS + 1:
        return offset == 0xa8 || offset == 0xb0 || offset == 0xd0 || offset == 0xd8;
    default:
        return false;
    }
}

static bool valid_access(unsigned window, uint64_t offset, unsigned size, bool write)
{
    if (window >= APPLE_MODERN_DVFM_WINDOWS || (size != 4 && size != 8) ||
        (offset & (size - 1)) || offset >= APPLE_MODERN_DVFM_SPAN) {
        return false;
    }
    if (window >= APPLE_MODERN_DVFM_TABLE_WINDOWS) {
        /* AppleT8140PMGR slotbc0 (0x984a6f4), after restoring ACC
         * counters: 64-bit RMW of +178, replacing top maska800... with
         * enable?a800...:0. v27 captures the actual first read through
         * the DBG alias. No poll; plain stored enable, no event producer. */
        if (offset == 0x178) {
            return size == 8;
        }
        return !write && size == 8 && control_register(window, offset);
    }
    return true;
}

static void touch(AppleModernDVFMCore *core, unsigned window, uint64_t offset)
{
    core->touched[window][offset / 512] |= UINT64_C(1) << ((offset / 8) % 64);
}

bool apple_modern_cpu_dvfm_core_touched(const AppleModernDVFMCore *core,
    unsigned window, uint64_t offset)
{
    return core && window < APPLE_MODERN_DVFM_WINDOWS &&
           offset < APPLE_MODERN_DVFM_SPAN &&
           (core->touched[window][offset / 512] >> ((offset / 8) % 64)) & 1;
}

bool apple_modern_cpu_dvfm_core_read(AppleModernDVFMCore *core, unsigned window,
    uint64_t offset, unsigned size, uint64_t *value)
{
    if (!core || !value || !valid_access(window, offset, size, false) ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    uint64_t word = core->words[window][offset / 8];
    *value = size == 8 ? word : (offset & 4) ? word >> 32 : word & UINT32_MAX;
    touch(core, window, offset);
    increment(&core->reads);
    return true;
}

bool apple_modern_cpu_dvfm_core_write(AppleModernDVFMCore *core, unsigned window,
    uint64_t offset, unsigned size, uint64_t value)
{
    if (!core || !valid_access(window, offset, size, true)) {
        return false;
    }
    uint64_t *word = &core->words[window][offset / 8];
    if (size == 8) {
        *word = value;
    } else if (offset & 4) {
        *word = (*word & UINT32_MAX) | (value & UINT32_MAX) << 32;
    } else {
        *word = (*word & ~(uint64_t)UINT32_MAX) | (value & UINT32_MAX);
    }
    touch(core, window, offset);
    increment(&core->writes);
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct DVFMView {
    AppleModernDVFMCore *core;
    unsigned index;
    uint64_t *rejected;     /* diagnostics only: one bit per 4-byte slot already announced */
} DVFMView;
struct AppleModernDVFMState {
    SysBusDevice parent_obj;
    AppleModernDVFMCore core;
    DVFMView views[APPLE_MODERN_DVFM_WINDOWS];
    MemoryRegion regions[APPLE_MODERN_DVFM_WINDOWS];
    uint64_t rejected[APPLE_MODERN_DVFM_WINDOWS][APPLE_MODERN_DVFM_SPAN / 4 / 64];
};
/* A rejected access inside a window is not logged by -d invalid_mem (it reports only unmapped
 * addresses); announce the first one per 4-byte slot so a run shows the next unattested access. */
static void announce_reject(DVFMView *view, hwaddr offset, unsigned size, const char *what)
{
    uint64_t slot = offset / 4;
    if (slot < APPLE_MODERN_DVFM_SPAN / 4 &&
        !((view->rejected[slot / 64] >> (slot % 64)) & 1)) {
        view->rejected[slot / 64] |= UINT64_C(1) << (slot % 64);
        info_report("apple-modern cpu-dvfm: REJECTED %s of window %u +0x%" HWADDR_PRIx
                    " (%u bytes)", what, view->index, offset, size);
    }
}
/* Each distinct 8-byte word is announced once (at most 4 x 512 lines), so a run
 * shows exactly which words the guest touched; no word is ever announced twice. */
static void announce(DVFMView *view, bool fresh, hwaddr offset, unsigned size,
                     const char *what)
{
    if (fresh) {
        info_report("apple-modern cpu-dvfm: first %s of window %u +0x%" HWADDR_PRIx
                    " (%u bytes)", what, view->index, offset, size);
    }
}
static MemTxResult dvfm_read(void *opaque, hwaddr offset, uint64_t *value,
                             unsigned size, MemTxAttrs attrs)
{
    DVFMView *view = opaque;
    bool fresh = !apple_modern_cpu_dvfm_core_touched(view->core, view->index, offset);
    if (!apple_modern_cpu_dvfm_core_read(view->core, view->index, offset, size, value)) {
        announce_reject(view, offset, size, "read");
        return MEMTX_ACCESS_ERROR;
    }
    announce(view, fresh, offset, size, "read");
    return MEMTX_OK;
}
static MemTxResult dvfm_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size, MemTxAttrs attrs)
{
    DVFMView *view = opaque;
    bool fresh = !apple_modern_cpu_dvfm_core_touched(view->core, view->index, offset);
    if (!apple_modern_cpu_dvfm_core_write(view->core, view->index, offset, size, value)) {
        announce_reject(view, offset, size, "write");
        return MEMTX_ACCESS_ERROR;
    }
    announce(view, fresh, offset, size, "write");
    return MEMTX_OK;
}
static const MemoryRegionOps dvfm_ops = {
    .read_with_attrs = dvfm_read, .write_with_attrs = dvfm_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 8},
};
static void dvfm_reset(DeviceState *dev)
{
    AppleModernDVFMState *s = APPLE_MODERN_CPU_DVFM(dev);
    apple_modern_cpu_dvfm_core_reset(&s->core);
    memset(s->rejected, 0, sizeof(s->rejected));
}
static void dvfm_realize(DeviceState *dev, Error **errp)
{
    AppleModernDVFMState *s = APPLE_MODERN_CPU_DVFM(dev);
    for (unsigned i = 0; i < APPLE_MODERN_DVFM_WINDOWS; i++) {
        s->views[i] = (DVFMView){&s->core, i, s->rejected[i]};
        static const char *const names[APPLE_MODERN_DVFM_WINDOWS] = {
            "apple-modern.cpu-dvfm-e", "apple-modern.cpu-dvfm-p",
            "apple-modern.cpu-dvfm-e-ctl", "apple-modern.cpu-dvfm-p-ctl"};
        memory_region_init_io(&s->regions[i], OBJECT(dev), &dvfm_ops, &s->views[i],
                              names[i], APPLE_MODERN_DVFM_SPAN);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernDVFMCore *core = &APPLE_MODERN_CPU_DVFM(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription dvfm_unmigratable = {
    .name = TYPE_APPLE_MODERN_CPU_DVFM, .unmigratable = 1,
};
static void dvfm_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = dvfm_realize;
    dc->vmsd = &dvfm_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, dvfm_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDVFMCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernDVFMCore, writes));
}
DeviceState *apple_modern_cpu_dvfm_new(void)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_CPU_DVFM);
    dvfm_reset(dev);
    return dev;
}
static const TypeInfo dvfm_type = {
    .name = TYPE_APPLE_MODERN_CPU_DVFM, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernDVFMState), .class_init = dvfm_class_init,
};
static void register_types(void) { type_register_static(&dvfm_type); }
type_init(register_types)
#endif
