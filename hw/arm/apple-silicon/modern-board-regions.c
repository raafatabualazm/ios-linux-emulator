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
                                     AppleModernBoardRegionPolicy policy,
                                     AppleModernBoardRegions *output,
                                     Error **errp)
{
    /*
     * coresight-reg is only backed for ALL_CORES (SMP bring-up): XNU
     * cpu_start() on the master processor (BootKC 0xfffffff00ad3c348) writes
     * the CoreSight lock-access key 0xc5acce55 to coresight+0xfb0 and takes a
     * synchronous abort if the bank is unmapped, killing cpu_boot_thread
     * before any secondary is started.
     */
    static const char *const properties[] = {"cpu-impl-reg", "cpm-impl-reg",
                                             "coresight-reg"};
    static const char *const names[] = {"apple-modern.cpu-impl-reg",
                                       "apple-modern.cpm-impl-reg",
                                       "apple-modern.coresight-reg"};
    AppleModernBoardRegions plan = {0};
    size_t cores, nprops;

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
    if (policy != APPLE_MODERN_BOARD_REGIONS_BOOT_CPU &&
        policy != APPLE_MODERN_BOARD_REGIONS_ALL_CORES) {
        error_setg(errp, "unknown modern CPU register window policy");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!valid_range(exclusions[i].physical_address, exclusions[i].size)) {
            error_setg(errp, "invalid modern board exclusion span");
            return false;
        }
    }
    cores = policy == APPLE_MODERN_BOARD_REGIONS_ALL_CORES
                ? APPLE_MODERN_BOARD_REGION_MAX_CORES : 1;
    nprops = policy == APPLE_MODERN_BOARD_REGIONS_ALL_CORES ? 3 : 2;
    for (size_t core = 0; core < cores; core++) {
        char path[32];

        snprintf(path, sizeof(path), "/cpus/cpu%zu", core);
        for (size_t i = 0; i < nprops; i++) {
            AppleModernBlob property;
            AppleModernBoardRegion *window;
            uint64_t base, size;
            bool duplicate = false;

            if (!apple_modern_adt_property(dtree, path, properties[i],
                                           &property, errp)) {
                return false;
            }
            if (property.size != 16) {
                error_setg(errp, "modern %s must contain exactly one 16-byte "
                           "tuple", properties[i]);
                return false;
            }
            base = get64(property.data);
            size = get64(property.data + 8);
            /*
             * Cores share a cluster's cpm-impl-reg, so the same span is named
             * several times. Back it once; a partial overlap is still a fault
             * in the tree and is refused below.
             */
            for (size_t j = 0; j < plan.count; j++) {
                if (plan.windows[j].physical_address == base &&
                    plan.windows[j].size == size) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                continue;
            }
            if (plan.count >= APPLE_MODERN_CPU_REGISTER_WINDOWS) {
                error_setg(errp, "modern CPU register windows exceed the "
                           "%d-window budget", APPLE_MODERN_CPU_REGISTER_WINDOWS);
                return false;
            }
            window = &plan.windows[plan.count];
            window->physical_address = base;
            window->size = size;
            if (!base || !valid_range(base, size) ||
                size > APPLE_MODERN_MAX_REGISTER_WINDOW ||
                size > APPLE_MODERN_MAX_REGISTER_TOTAL - plan.total_size) {
                error_setg(errp, "modern %s exceeds register-RAM bounds",
                           properties[i]);
                return false;
            }
            if (range_overlap(base, size, dram_base, dram_size)) {
                error_setg(errp, "modern %s overlaps DRAM", properties[i]);
                return false;
            }
            for (size_t j = 0; j < exclusion_count; j++) {
                if (range_overlap(base, size, exclusions[j].physical_address,
                                  exclusions[j].size)) {
                    error_setg(errp, "modern %s overlaps another board mapping",
                               properties[i]);
                    return false;
                }
            }
            for (size_t j = 0; j < plan.count; j++) {
                if (range_overlap(base, size, plan.windows[j].physical_address,
                                  plan.windows[j].size)) {
                    error_setg(errp, "modern CPU register windows overlap");
                    return false;
                }
            }
            if (cores == 1) {
                memcpy(window->name, names[i], strlen(names[i]) + 1);
            } else {
                snprintf(window->name, sizeof(window->name),
                         "apple-modern.cpu%zu-%s", core, properties[i]);
            }
            plan.total_size += size;
            plan.count++;
        }
    }
    *output = plan;
    return true;
}
