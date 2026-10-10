/* Declared, default-off ASC v6 wrapper apertures for /arm-io/dcp.  See the
 * header for exactly what is attested and what is declared: three decoded
 * registers, an empty mailbox with no peer, and no endpoint.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
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
#include "hw/arm/apple-silicon/modern-dcp-asc.h"

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

/* Wrapper-block offsets.  ATTESTED as touched by the driver (header). */
#define REG_IDLE_CTRL 0x40     /* read; idle-ctrl-check bit test */
#define REG_CPU_CTRL 0x44      /* read and write; RUN = bit 4 */
#define REG_CPU_STATUS 0x48    /* read; semantics unknown, see header */
#define CPU_CTRL_RUN_BIT (1u << 4)
#define REG_DOORBELL_A 0x1004  /* write */
#define REG_DOORBELL_B 0x1014  /* write */
#define REG_IDLE_STATUS 0x8000 /* read */
#define IDLE_STATUS_IDLE 0x3
#define REG_A2I_CONTROL 0x8110 /* read */
#define REG_I2A_CONTROL 0x8114 /* read and write */
#define MAILBOX_CONTROL_EMPTY (1u << 17)
#define REG_SEND_LOW 0x8800    /* 128-bit store, i.e. 0x8800 and 0x8808 */
#define REG_SEND_HIGH 0x8808
#define REG_RECV_LOW 0x8830    /* 128-bit load, i.e. 0x8830 and 0x8838 */
#define REG_RECV_HIGH 0x8838
#define REG_DUMP_FIRST 0x8180  /* 128 words, 4 bytes apart */
#define REG_DUMP_WORDS 128

static const char *const window_names[APPLE_MODERN_DCP_ASC_CANDIDATES] = {
    "wrapper", "core", "wrapper-alias"
};

const char *apple_modern_dcp_asc_window_name(unsigned candidate)
{
    return candidate < APPLE_MODERN_DCP_ASC_CANDIDATES ?
           window_names[candidate] : "?";
}

bool apple_modern_dcp_asc_mode(const char *name, unsigned *mode)
{
    if (!name || !mode) {
        return false;
    }
    if (!strcmp(name, APPLE_MODERN_DCP_ASC_MODE_LOADED)) {
        *mode = APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED;
        return true;
    }
    if (!strcmp(name, APPLE_MODERN_DCP_ASC_MODE_ABSENT)) {
        *mode = APPLE_MODERN_DCP_ASC_FIRMWARE_ABSENT;
        return true;
    }
    return false;
}

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

static bool overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    return as && bs && a < b + bs && b < a + as;
}

bool apple_modern_dcp_asc_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDcpAscPlan *output, Error **errp)
{
    static const uint64_t expected[APPLE_MODERN_DCP_ASC_WINDOWS] = {
        APPLE_MODERN_DCP_ASC_WRAPPER_SIZE, APPLE_MODERN_DCP_ASC_CORE_SIZE,
        APPLE_MODERN_DCP_ASC_ALIAS_SIZE
    };
    AppleModernDcpAscPlan plan;
    AppleModernBlob ranges, reg, compatible;

    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "dcp-asc output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    memset(&plan, 0, sizeof(plan));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "dcp-asc DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size ||
            exclusions[i].size > UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "dcp-asc exclusion is empty or wraps");
            return false;
        }
    }
    /*
     * The node must still be an ASC v6 wrapper in the tree actually served.
     * The served Darwin-derived tree strips "compatible", and disp0-probe puts
     * the stock bytes back, so this check is what ties the model to the arm
     * that makes the driver match at all: without the restored compatible no
     * AppleASCWrapV6 exists and these apertures would have no reader.
     */
    if (!apple_modern_adt_property(tree, "/arm-io/dcp", "compatible",
                                   &compatible, errp) ||
        compatible.size != sizeof("iop,ascwrap-v6") ||
        memcmp(compatible.data, "iop,ascwrap-v6", compatible.size)) {
        if (errp && !*errp) {
            error_setg(errp, "dcp-asc needs /arm-io/dcp compatible "
                             "\"iop,ascwrap-v6\" in the served tree; combine "
                             "it with a disp0-probe arm that restores it");
        }
        return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp) ||
        !ranges.size || ranges.size % 24) {
        if (errp && !*errp) {
            error_setg(errp, "dcp-asc requires /arm-io ranges");
        }
        return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io/dcp", "reg", &reg, errp) ||
        reg.size != APPLE_MODERN_DCP_ASC_WINDOWS * 16) {
        if (errp && !*errp) {
            error_setg(errp, "dcp-asc requires exactly %u /arm-io/dcp reg "
                             "windows", APPLE_MODERN_DCP_ASC_WINDOWS);
        }
        return false;
    }
    for (unsigned e = 0; e < APPLE_MODERN_DCP_ASC_WINDOWS; e++) {
        uint64_t bus = little(reg.data + e * 16, 8);
        uint64_t size = little(reg.data + e * 16 + 8, 8);
        uint64_t address = 0;
        unsigned matches = 0;

        if (size != expected[e]) {
            error_setg(errp, "/arm-io/dcp reg[%u] size 0x%llx is not the "
                       "attested 0x%llx", e, (unsigned long long)size,
                       (unsigned long long)expected[e]);
            return false;
        }
        if (size > UINT64_MAX - bus) {
            error_setg(errp, "/arm-io/dcp reg[%u] wraps", e);
            return false;
        }
        for (size_t i = 0; i < ranges.size; i += 24) {
            uint64_t c = little(ranges.data + i, 8);
            uint64_t p = little(ranges.data + i + 8, 8);
            uint64_t n = little(ranges.data + i + 16, 8);
            if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
                error_setg(errp, "dcp-asc bus range is empty or wraps");
                return false;
            }
            if (bus >= c && bus - c < n && size <= n - (bus - c)) {
                address = p + (bus - c);
                matches++;
            }
        }
        if (matches != 1) {
            error_setg(errp, "/arm-io/dcp reg[%u] is outside /arm-io or "
                       "ambiguous", e);
            return false;
        }
        if (overlaps(address, size, dram_base, dram_size)) {
            error_setg(errp, "/arm-io/dcp reg[%u] lands in DRAM", e);
            return false;
        }
        for (size_t i = 0; i < exclusion_count; i++) {
            if (overlaps(address, size, exclusions[i].physical_address,
                         exclusions[i].size)) {
                error_setg(errp, "/arm-io/dcp reg[%u] overlaps an already "
                           "mapped device", e);
                return false;
            }
        }
        /*
         * reg[2] is inside reg[0] in this ADT.  A contained candidate is
         * SKIPPED, exactly as the disp0 trace plan does, so the same bytes are
         * never mapped twice; a PARTIAL overlap is refused, because it would
         * mean the layout is not the one this model was derived from.
         */
        for (unsigned i = 0; i < e; i++) {
            if (plan.contained[i]) {
                continue;
            }
            if (address >= plan.addresses[i] && size <= plan.sizes[i] &&
                address - plan.addresses[i] <= plan.sizes[i] - size) {
                plan.contained[e] = true;
            } else if (overlaps(address, size, plan.addresses[i],
                                plan.sizes[i])) {
                error_setg(errp, "/arm-io/dcp reg[%u] partly overlaps reg[%u]",
                           e, i);
                return false;
            }
        }
        plan.addresses[e] = address;
        plan.sizes[e] = size;
        plan.count++;
        plan.mapped += !plan.contained[e];
    }
    if (plan.mapped != APPLE_MODERN_DCP_ASC_MAPPED) {
        error_setg(errp, "/arm-io/dcp has %u disjoint windows, not the "
                   "attested %u", plan.mapped, APPLE_MODERN_DCP_ASC_MAPPED);
        return false;
    }
    *output = plan;
    return true;
}

void apple_modern_dcp_asc_core_reset(AppleModernDcpAscCore *core,
                                     unsigned mode)
{
    if (!core) {
        return;
    }
    memset(core, 0, sizeof(*core));
    core->mode = mode;
}

static void note(AppleModernDcpAscCore *core, unsigned window, uint64_t offset,
                 unsigned size, bool write, bool modelled)
{
    if (!core || window >= APPLE_MODERN_DCP_ASC_MAPPED) {
        return;
    }
    if (write) {
        core->writes += core->writes != UINT64_MAX;
        core->window_writes[window] += core->window_writes[window] != UINT64_MAX;
    } else {
        core->reads += core->reads != UINT64_MAX;
        core->window_reads[window] += core->window_reads[window] != UINT64_MAX;
    }
    if (apple_modern_dcp_asc_core_recorded(core, window, offset, write)) {
        return;
    }
    if (core->record_count >= APPLE_MODERN_DCP_ASC_RECORDS) {
        core->dropped += core->dropped != UINT64_MAX;
        return;
    }
    core->records[core->record_count] = (AppleModernDcpAscRecord){
        offset, (uint8_t)window, (uint8_t)size, write, modelled};
    core->record_count++;
    if (!modelled && !core->first_unmodelled) {
        core->first_unmodelled = core->record_count;
    }
#ifndef APPLE_MODERN_LAYOUT_STANDALONE
    warn_report("apple-modern: dcp-asc #%u %s %s offset 0x%" PRIx64 " size %u%s",
                core->record_count, write ? "write" : "read",
                apple_modern_dcp_asc_window_name(window), offset, size,
                modelled ? "" : " UNMODELLED (answered zero)");
#endif
}

bool apple_modern_dcp_asc_core_recorded(const AppleModernDcpAscCore *core,
    unsigned window, uint64_t offset, bool write)
{
    if (!core) {
        return false;
    }
    for (unsigned i = 0; i < core->record_count; i++) {
        const AppleModernDcpAscRecord *r = &core->records[i];
        if (r->window == window && r->offset == offset &&
            r->write == (write ? 1 : 0)) {
            return true;
        }
    }
    return false;
}

static bool dump_word(uint64_t offset)
{
    return offset >= REG_DUMP_FIRST &&
           offset < REG_DUMP_FIRST + (uint64_t)REG_DUMP_WORDS * 4 &&
           !(offset % 4);
}

void apple_modern_dcp_asc_core_read(AppleModernDcpAscCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t *value)
{
    uint64_t answer = 0;
    bool modelled = false;

    if (value) {
        *value = 0;
    }
    if (!core || window >= APPLE_MODERN_DCP_ASC_MAPPED) {
        return;
    }
    if (window == APPLE_MODERN_DCP_ASC_WRAPPER) {
        switch (offset) {
        case REG_IDLE_CTRL:
            /* DECLARED: /arm-io/dcp carries idle-ctrl-check and the driver
             * only bit-tests this word. */
            answer = 1;
            modelled = true;
            break;
        case REG_CPU_CTRL:
            answer = core->cpu_ctrl;
            modelled = true;
            break;
        case REG_CPU_STATUS:
            /* DECLARED: no source agrees on the bits and XNU never reads it on
             * a path reachable from start(); report nothing. */
            answer = 0;
            modelled = true;
            break;
        case REG_IDLE_STATUS:
            answer = core->running ? 0 : IDLE_STATUS_IDLE;
            modelled = true;
            break;
        case REG_A2I_CONTROL:
        case REG_I2A_CONTROL:
            /* DECLARED: there is no peer, so both directions are empty and the
             * occupancy field (23:20) is zero. */
            answer = MAILBOX_CONTROL_EMPTY;
            modelled = true;
            break;
        case REG_RECV_LOW:
        case REG_RECV_HIGH:
            core->mailbox_recv_polls += core->mailbox_recv_polls != UINT64_MAX;
            answer = 0;
            modelled = true;
            break;
        default:
            if (dump_word(offset)) {
                answer = 0;
                modelled = true;
            }
            break;
        }
    } else if (window == APPLE_MODERN_DCP_ASC_CORE && offset == 0) {
        /*
         * The one attested predicate in the whole model: AppleASCWrapV6 reads
         * 64 bits here and panics "ASC firmware must be loaded by iBoot" when
         * bit 0 is clear.  Setting it is a DECLARED CLAIM that iBoot loaded the
         * DCP firmware; this loader did not.
         */
        core->firmware_bit_reads += core->firmware_bit_reads != UINT64_MAX;
        answer = core->mode == APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED ? 1 : 0;
        modelled = true;
    }
    note(core, window, offset, size, false, modelled);
    if (value) {
        if (size >= 8) {
            *value = answer;
        } else {
            *value = answer & ((UINT64_C(1) << (size * 8)) - 1);
        }
    }
}

void apple_modern_dcp_asc_core_write(AppleModernDcpAscCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t value)
{
    bool modelled = false;

    if (!core || window >= APPLE_MODERN_DCP_ASC_MAPPED) {
        return;
    }
    if (window == APPLE_MODERN_DCP_ASC_WRAPPER) {
        switch (offset) {
        case REG_CPU_CTRL:
            core->cpu_ctrl = (uint32_t)value;
            if (value & CPU_CTRL_RUN_BIT) {
                core->running = true;
            }
            modelled = true;
            break;
        case REG_DOORBELL_A:
        case REG_DOORBELL_B:
            core->doorbells += core->doorbells != UINT64_MAX;
            modelled = true;
            break;
        case REG_SEND_LOW:
        case REG_SEND_HIGH:
            /* Counted and DISCARDED: nothing receives it. */
            core->mailbox_sends += core->mailbox_sends != UINT64_MAX;
            modelled = true;
            break;
        case REG_I2A_CONTROL:
            modelled = true;
            break;
        default:
            break;
        }
    }
    note(core, window, offset, size, true, modelled);
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct DcpAscView {
    AppleModernDcpAscCore *core;
    unsigned index;
} DcpAscView;

struct AppleModernDcpAscState {
    SysBusDevice parent_obj;
    AppleModernDcpAscCore core;
    AppleModernDcpAscPlan plan;
    unsigned mode;
    DcpAscView views[APPLE_MODERN_DCP_ASC_WINDOWS];
    MemoryRegion regions[APPLE_MODERN_DCP_ASC_WINDOWS];
};

static uint64_t dcp_asc_read(void *opaque, hwaddr offset, unsigned size)
{
    DcpAscView *view = opaque;
    uint64_t value = 0;
    apple_modern_dcp_asc_core_read(view->core, view->index, offset, size,
                                   &value);
    return value;
}

static void dcp_asc_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    DcpAscView *view = opaque;
    apple_modern_dcp_asc_core_write(view->core, view->index, offset, size,
                                    value);
}

static const MemoryRegionOps dcp_asc_ops = {
    .read = dcp_asc_read, .write = dcp_asc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8, .unaligned = true},
    .impl = {.min_access_size = 1, .max_access_size = 8, .unaligned = true},
};

static void dcp_asc_reset(DeviceState *dev)
{
    AppleModernDcpAscState *s = APPLE_MODERN_DCP_ASC(dev);
    apple_modern_dcp_asc_core_reset(&s->core, s->mode);
}

static void dcp_asc_realize(DeviceState *dev, Error **errp)
{
    AppleModernDcpAscState *s = APPLE_MODERN_DCP_ASC(dev);

    unsigned region = 0;

    if (s->plan.count != APPLE_MODERN_DCP_ASC_CANDIDATES ||
        s->plan.mapped != APPLE_MODERN_DCP_ASC_MAPPED) {
        error_setg(errp, "dcp-asc plan does not carry %u candidates with %u "
                   "mapped", APPLE_MODERN_DCP_ASC_CANDIDATES,
                   APPLE_MODERN_DCP_ASC_MAPPED);
        return;
    }
    for (unsigned i = 0; i < s->plan.count; i++) {
        char *name;
        if (s->plan.contained[i]) {
            continue;
        }
        name = g_strdup_printf("apple-modern.dcp-asc.%s",
                               apple_modern_dcp_asc_window_name(i));
        s->views[region] = (DcpAscView){&s->core, region};
        memory_region_init_io(&s->regions[region], OBJECT(dev), &dcp_asc_ops,
                              &s->views[region], name, s->plan.sizes[i]);
        g_free(name);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[region]);
        region++;
    }
}

static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernDcpAscCore *core = &APPLE_MODERN_DCP_ASC(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}

static void get_unsigned(Object *obj, Visitor *v, const char *name,
                         void *opaque, Error **errp)
{
    AppleModernDcpAscCore *core = &APPLE_MODERN_DCP_ASC(obj)->core;
    uint64_t value = *(unsigned *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}

static const VMStateDescription dcp_asc_unmigratable = {
    .name = TYPE_APPLE_MODERN_DCP_ASC, .unmigratable = 1,
};

static void dcp_asc_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = dcp_asc_realize;
    dc->vmsd = &dcp_asc_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, dcp_asc_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore, writes));
    object_class_property_add(oc, "wrapper-read-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore, window_reads));
    object_class_property_add(oc, "core-read-count", "uint64", get_counter,
        NULL, NULL, (void *)(offsetof(AppleModernDcpAscCore, window_reads) +
                             sizeof(uint64_t)));
    object_class_property_add(oc, "firmware-bit-reads", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore,
                                     firmware_bit_reads));
    object_class_property_add(oc, "doorbells", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore, doorbells));
    object_class_property_add(oc, "mailbox-sends", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore, mailbox_sends));
    object_class_property_add(oc, "mailbox-recv-polls", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore,
                                     mailbox_recv_polls));
    object_class_property_add(oc, "record-count", "uint64", get_unsigned,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore, record_count));
    object_class_property_add(oc, "first-unmodelled", "uint64", get_unsigned,
        NULL, NULL, (void *)offsetof(AppleModernDcpAscCore, first_unmodelled));
}

DeviceState *apple_modern_dcp_asc_new(const AppleModernDcpAscPlan *plan,
                                      unsigned mode)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_DCP_ASC);
    AppleModernDcpAscState *s = APPLE_MODERN_DCP_ASC(dev);
    if (plan) {
        s->plan = *plan;
    }
    s->mode = mode;
    dcp_asc_reset(dev);
    return dev;
}

static const TypeInfo dcp_asc_types[] = {
    {
        .name = TYPE_APPLE_MODERN_DCP_ASC,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(AppleModernDcpAscState),
        .class_init = dcp_asc_class_init,
    },
};
DEFINE_TYPES(dcp_asc_types)
#endif
