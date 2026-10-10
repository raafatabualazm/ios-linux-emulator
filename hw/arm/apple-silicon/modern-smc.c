/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "system/reset.h"
#include "hw/misc/apple-silicon/smc.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#endif
#include "hw/arm/apple-silicon/modern-smc.h"
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
static void error_setg(Error **errp, const char *format, ...)
{
    if (errp) {
        va_list ap;
        *errp = calloc(1, sizeof(**errp));
        if (!*errp) { abort(); }
        va_start(ap, format);
        vsnprintf((*errp)->message, sizeof((*errp)->message), format, ap);
        va_end(ap);
    }
}
#endif
static uint64_t little(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) { v |= (uint64_t)p[i] << (8 * i); }
    return v;
}
static bool range_valid(uint64_t base, uint64_t size)
{
    return size && size <= UINT64_MAX - base;
}
static bool overlap(uint64_t a, uint64_t n, uint64_t b, uint64_t m)
{
    return a < b + m && b < a + n;
}
static const uint8_t one[] = {1, 0, 0, 0};
static const AppleModernAdtOverride flags[] = {
    {"/arm-io/smc/iop-smc-nub", "pre-loaded", one, sizeof(one)},
    {"/arm-io/smc/iop-smc-nub", "running", one, sizeof(one)},
};
const AppleModernAdtOverride *apple_modern_smc_overrides(size_t *count)
{
    if (count) { *count = sizeof(flags) / sizeof(flags[0]); }
    return flags;
}
bool apple_modern_smc_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernSMCPlan *out, Error **errp)
{
    AppleModernSMCPlan plan = {0};
    AppleModernBlob reg, ranges, prop;
    const uint64_t lengths[] = {0x88000, 0x4000, 0x100, 0x100000};
    const char *nub = "/arm-io/smc/iop-smc-nub";
    if (!out || !tree.data || !tree.size ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) || !range_valid(dram_base, dram_size)) {
        error_setg(errp, "modern-smc: invalid plan arguments"); return false;
    }
    /* Output may not alias serialized input or the caller's exclusions. */
    uintptr_t output_base = (uintptr_t)out, input_base = (uintptr_t)tree.data;
    uintptr_t exclusion_base = (uintptr_t)exclusions;
    size_t exclusion_bytes = exclusion_count * sizeof(*exclusions);
    if (!range_valid(output_base, sizeof(*out)) ||
        !range_valid(input_base, tree.size) ||
        overlap(output_base, sizeof(*out), input_base, tree.size) ||
        (exclusion_bytes && (!range_valid(exclusion_base, exclusion_bytes) ||
         overlap(output_base, sizeof(*out), exclusion_base, exclusion_bytes)))) {
        error_setg(errp, "modern-smc: aliased or wrapping input/output"); return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io/smc", "compatible", &prop, errp) ||
        prop.size != sizeof("iop,ascwrap-v6") ||
        memcmp(prop.data, "iop,ascwrap-v6", prop.size)) {
        if (errp && !*errp) { error_setg(errp, "modern-smc needs the stock ASC compatible"); }
        return false;
    }
    if (!apple_modern_adt_property(tree, nub, "compatible", &prop, errp) ||
        prop.size != sizeof("iop-nub,rtbuddy-v2") ||
        memcmp(prop.data, "iop-nub,rtbuddy-v2", prop.size)) {
        if (errp && !*errp) { error_setg(errp, "modern-smc needs the stock RTBuddy compatible"); }
        return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io/smc", "role", &prop, errp) ||
        prop.size != sizeof("SMC") || memcmp(prop.data, "SMC", sizeof("SMC"))) {
        if (errp && !*errp) { error_setg(errp, "modern-smc requires role SMC"); }
        return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io/smc", "reg", &reg, errp) || reg.size != 48 ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp) ||
        !ranges.size || ranges.size % 24) {
        if (errp && !*errp) { error_setg(errp, "modern-smc requires three reg tuples and bus ranges"); }
        return false;
    }
    for (size_t i = 0; i < 3; i++) {
        uint64_t bus = little(reg.data + i * 16, 8);
        size_t matches = 0;
        plan.size[i] = little(reg.data + i * 16 + 8, 8);
        if (plan.size[i] != lengths[i] || !range_valid(bus, plan.size[i])) {
            error_setg(errp, "modern-smc reg[%zu] has unsupported geometry", i); return false;
        }
        for (size_t j = 0; j < ranges.size; j += 24) {
            uint64_t child = little(ranges.data + j, 8), parent = little(ranges.data + j + 8, 8);
            uint64_t size = little(ranges.data + j + 16, 8);
            if (!range_valid(child, size) || !range_valid(parent, size)) {
                error_setg(errp, "modern-smc bus range wraps or is empty"); return false;
            }
            if (bus >= child && bus - child < size && plan.size[i] <= size - (bus - child)) {
                plan.address[i] = parent + bus - child; matches++;
            }
        }
        if (matches != 1) {
            error_setg(errp, "modern-smc reg[%zu] has ambiguous/missing translation", i); return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io/smc", "timers-reg-index", &prop, errp) ||
        prop.size != 4 || little(prop.data, 4) != 2) {
        if (errp && !*errp) { error_setg(errp, "modern-smc requires timers-reg-index 2"); }
        return false;
    }
    if (!apple_modern_adt_property(tree, nub, "region-base", &prop, errp) || prop.size != 8) {
        if (errp && !*errp) { error_setg(errp, "modern-smc requires a 64-bit SRAM base"); }
        return false;
    }
    plan.address[3] = little(prop.data, 8);
    if (!apple_modern_adt_property(tree, nub, "region-size", &prop, errp) || prop.size != 8 ||
        (plan.size[3] = little(prop.data, 8)) != lengths[3]) {
        if (errp && !*errp) { error_setg(errp, "modern-smc requires 1 MiB SRAM"); }
        return false;
    }
    for (size_t i = 0; i < 4; i++) {
        if (!range_valid(plan.address[i], plan.size[i]) ||
            overlap(plan.address[i], plan.size[i], dram_base, dram_size)) {
            error_setg(errp, "modern-smc window %zu wraps or overlaps DRAM", i); return false;
        }
        for (size_t j = 0; j < i; j++) {
            if (overlap(plan.address[i], plan.size[i], plan.address[j], plan.size[j])) {
                error_setg(errp, "modern-smc windows overlap"); return false;
            }
        }
        for (size_t j = 0; j < exclusion_count; j++) {
            if (!range_valid(exclusions[j].physical_address, exclusions[j].size) ||
                overlap(plan.address[i], plan.size[i], exclusions[j].physical_address, exclusions[j].size)) {
                error_setg(errp, "modern-smc window %zu overlaps/has invalid exclusion", i); return false;
            }
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io/smc", "interrupts", &prop, errp) || prop.size != 16) {
        if (errp && !*errp) { error_setg(errp, "modern-smc requires four IRQs"); }
        return false;
    }
    for (size_t i = 0; i < 4; i++) {
        plan.interrupts[i] = little(prop.data + 4 * i, 4);
        if (!plan.interrupts[i]) { error_setg(errp, "modern-smc zero IRQ"); return false; }
        for (size_t j = 0; j < i; j++) {
            if (plan.interrupts[i] == plan.interrupts[j]) { error_setg(errp, "modern-smc duplicate IRQ"); return false; }
        }
    }
    *out = plan;
    return true;
}
#ifndef APPLE_MODERN_LAYOUT_STANDALONE
/* Modern-only child apertures: the shared legacy SMC model remains unchanged. */
static uint64_t smc_loaded_read(void *opaque, hwaddr addr, unsigned size)
{
    return addr == 0 ? 1 : 0;
}
static void smc_loaded_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "modern-smc: ignored firmware-loaded write +0x%" HWADDR_PRIx " value 0x%" PRIx64 "\n", addr, value);
}
static const MemoryRegionOps loaded_ops = {
    .read = smc_loaded_read, .write = smc_loaded_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 8,
    .impl.min_access_size = 4, .impl.max_access_size = 8,
};
static uint64_t smc_timer_read(void *opaque, hwaddr addr, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "modern-smc: unmodelled timer read +0x%" HWADDR_PRIx " size %u\n", addr, size);
    return 0;
}
static void smc_timer_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "modern-smc: unmodelled timer write +0x%" HWADDR_PRIx " size %u value 0x%" PRIx64 "\n", addr, size, value);
}
static const MemoryRegionOps timer_ops = {
    .read = smc_timer_read, .write = smc_timer_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 8,
    .impl.min_access_size = 4, .impl.max_access_size = 8,
};
static void modern_smc_reset(void *opaque)
{
    /* Keep the modern declared reset coherent. The shared legacy reset keeps
     * CPU_CTRL, so reset it here only for this default-off modern adapter. */
    apple_a7iop_set_cpu_ctrl(APPLE_A7IOP(opaque), 0);
}
typedef struct ModernSMCKeyTap {
    AppleRTKitEPData original;
} ModernSMCKeyTap;
static void modern_smc_key_message(void *opaque, uint8_t ep, uint64_t message)
{
    ModernSMCKeyTap *tap = opaque;
    uint32_t key = message >> 32;
    qemu_log_mask(LOG_GUEST_ERROR,
                  "modern-smc: cmd=0x%02x key=0x%08x [%c%c%c%c] length=%u payload_length=%u\n",
                  (unsigned)(message & 0xff), key, SMC_KEY_FORMAT(key),
                  (unsigned)((message >> 16) & 0xff),
                  (unsigned)((message >> 24) & 0xff));
    tap->original.handler(tap->original.opaque, ep, message);
}
SysBusDevice *apple_modern_smc_new(const AppleModernSMCPlan *plan)
{
    /* The legacy constructor needs two reg tuples to SIZE its wrapper/core.
     * Build a small private adapter node. It never serialises into guest ADT. */
    AppleDTNode *root = apple_dt_node_new(NULL, "adapter");
    AppleDTNode *node = apple_dt_node_new(root, "smc");
    uint64_t reg[] = {0, plan->size[0], 0, plan->size[1]};
    MemoryRegion *loaded = g_new0(MemoryRegion, 1);
    MemoryRegion *timers = g_new0(MemoryRegion, 1);
    SysBusDevice *dev;
    ModernSMCKeyTap *tap = g_new0(ModernSMCKeyTap, 1);
    apple_dt_set_prop(node, "reg", sizeof(reg), reg);
    apple_dt_node_new(node, "iop-smc-nub");
    dev = apple_smc_create(node, APPLE_A7IOP_V6, plan->size[3]);
    AppleRTKit *rtk = APPLE_RTKIT(dev);
    const AppleRTKitEPData *entry = AppleRTKitEPTable_get(rtk->endpoints, 32);
    if (!entry || !entry->handler) {
        error_setg(&error_fatal, "modern-smc missing legacy key endpoint");
    }
    tap->original = *entry;
    apple_rtkit_unregister_user_ep(rtk, 0);
    apple_rtkit_register_user_ep(rtk, 0, tap, modern_smc_key_message);
    apple_dt_del_node(root, node);
    g_hash_table_destroy(root->props);
    g_free(root);
    memory_region_init_io(loaded, OBJECT(dev), &loaded_ops, dev, "modern-smc.loaded", 8);
    memory_region_add_subregion_overlap(sysbus_mmio_get_region(dev, 1), 0, loaded, 1);
    memory_region_init_io(timers, OBJECT(dev), &timer_ops, dev, "modern-smc.timers", plan->size[2]);
    sysbus_init_mmio(dev, timers); /* index 3, after legacy wrapper/core/SRAM */
    qemu_register_reset(modern_smc_reset, dev);
    return dev;
}
#endif
