/*
 * Bounded CPU implementation register-RAM compatibility plan.
 * Reference: Darwin-VM qemu-sptm 2867d847, darwin.c:init_cpu_impl().
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/modern-board-regions.h"

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

static uint64_t get64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) {
        value |= (uint64_t)p[i] << (8 * i);
    }
    return value;
}

static bool pointer_overlap(const void *a, size_t as, const void *b, size_t bs)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;

    if (!as || !bs) {
        return false;
    }
    if (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y) {
        return true;
    }
    return x < y + bs && y < x + as;
}

static bool valid_range(uint64_t base, uint64_t size)
{
    return size && size <= UINT64_MAX - base;
}

static bool range_overlap(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    return a < b + bs && b < a + as;
}

bool apple_modern_board_regions_build(AppleModernBlob dtree,
                                     uint64_t dram_base, uint64_t dram_size,
                                     const AppleModernAddressRange *exclusions,
                                     size_t exclusion_count,
                                     AppleModernBoardRegions *output,
                                     Error **errp)
{
    static const char *const properties[] = {"cpu-impl-reg", "cpm-impl-reg"};
    static const char *const names[] = {"apple-modern.cpu-impl-reg",
                                       "apple-modern.cpm-impl-reg"};
    AppleModernBoardRegions plan = {0};

    if (!output) {
        error_setg(errp, "missing modern board region output");
        return false;
    }
    if (pointer_overlap(output, sizeof(*output), dtree.data, dtree.size) ||
        exclusion_count > SIZE_MAX / sizeof(*exclusions) ||
        (exclusions && pointer_overlap(output, sizeof(*output), exclusions,
                         exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "modern board region output aliases input");
        return false;
    }
    memset(output, 0, sizeof(*output));
    if (!valid_range(dram_base, dram_size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions)) {
        error_setg(errp, "invalid modern DRAM or exclusion list");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!valid_range(exclusions[i].physical_address, exclusions[i].size)) {
            error_setg(errp, "invalid modern board exclusion span");
            return false;
        }
    }
    for (size_t i = 0; i < APPLE_MODERN_CPU_REGISTER_WINDOWS; i++) {
        AppleModernBlob property;
        AppleModernBoardRegion *window = &plan.windows[i];

        if (!apple_modern_adt_property(dtree, "/cpus/cpu0", properties[i],
                                       &property, errp)) {
            return false;
        }
        if (property.size != 16) {
            error_setg(errp, "modern %s must contain exactly one 16-byte tuple",
                       properties[i]);
            return false;
        }
        window->physical_address = get64(property.data);
        window->size = get64(property.data + 8);
        if (!window->physical_address ||
            !valid_range(window->physical_address, window->size) ||
            window->size > APPLE_MODERN_MAX_REGISTER_WINDOW ||
            window->size > APPLE_MODERN_MAX_REGISTER_TOTAL - plan.total_size) {
            error_setg(errp, "modern %s exceeds register-RAM bounds",
                       properties[i]);
            return false;
        }
        if (range_overlap(window->physical_address, window->size,
                          dram_base, dram_size)) {
            error_setg(errp, "modern %s overlaps DRAM", properties[i]);
            return false;
        }
        for (size_t j = 0; j < exclusion_count; j++) {
            if (range_overlap(window->physical_address, window->size,
                              exclusions[j].physical_address,
                              exclusions[j].size)) {
                error_setg(errp, "modern %s overlaps another board mapping",
                           properties[i]);
                return false;
            }
        }
        for (size_t j = 0; j < i; j++) {
            if (range_overlap(window->physical_address, window->size,
                              plan.windows[j].physical_address,
                              plan.windows[j].size)) {
                error_setg(errp, "modern CPU register windows overlap");
                return false;
            }
        }
        memcpy(window->name, names[i], strlen(names[i]) + 1);
        plan.total_size += window->size;
        plan.count++;
    }
    *output = plan;
    return true;
}
