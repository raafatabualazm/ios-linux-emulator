/* disp0 bind probe: declared ADT compatible overrides plus logging apertures
 * over the display register windows.  See the header for what is attested and
 * what is declared.
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
#include "hw/arm/apple-silicon/modern-disp-trace.h"

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

/*
 * Byte-exact stock values.  Attested: read out of
 * runtime/darwin-reference-27/dtree.stock (sha256 pinned in the evidence
 * README) with the project's ADT walker; the served tree carries none of them.
 */
static const uint8_t compat_disp0[] = "disp0,t8140";          /* 12 B with NUL */
static const uint8_t compat_dcp[] = "iop,ascwrap-v6";         /* 15 B */
static const uint8_t compat_dcp_nub[] = "iop-nub,rtbuddy-v2"; /* 19 B */
static const uint8_t compat_dcp_expert[] = "dcp-expert-v1";   /* 14 B */
static const uint8_t compat_dart[] = "dart,t8110";            /* 11 B */
static const uint8_t compat_iommu_mapper[] = "iommu-mapper";  /* 13 B */
/* DECLARED, not in the stock tree: a 4-byte non-zero value for the property
 * the kext's own accessor reads ("found ? value : 0"). */
static const uint8_t no_dcp_driver_one[4] = {1, 0, 0, 0};
/* DECLARED dart-id values. The served tree carries no dart,t8110 node at all,
 * so 0 and 1 are free; iBoot's own numbering is unmeasured. */
static const uint8_t dart_id_0[4] = {0, 0, 0, 0};
static const uint8_t dart_id_1[4] = {1, 0, 0, 0};
/*
 * Positive control for the override path itself (attested stock values).  Two
 * /arm-io nodes whose reg property is EMPTY, so a driver that binds to them
 * cannot touch an unmodelled register: their personalities are
 * AppleEmbeddedAudioResourceManager ("audio,embedded-resource-manager") and
 * IOPAudioController ("iop-audio,controller"), both IOProviderClass
 * AppleARMIODevice with no further match key - the same matching shape
 * AppleCLCD2 uses.  If these appear in the guest's IOKit registration log and
 * AppleCLCD2 does not, the override mechanism is not the missing piece.
 */
static const uint8_t compat_audio_rm[] = "audio,embedded-resource-manager";
static const uint8_t compat_iop_audio[] = "iop-audio,controller";
/*
 * Paired differential control for the power/clock-gate explanation (attested
 * stock values).  /arm-io/jpeg0-h17p carries "power-gates" and "clock-gates"
 * exactly as /arm-io/disp0 does, has nothing to do with the display, and its
 * AppleJPEGDriver personality has the same match shape; the audio node in the
 * same arm carries no gate property.  Restoring both in one boot puts a gated
 * and an ungated node side by side.
 */
/* Two NUL-separated entries, exactly as the stock tree stores them. */
static const uint8_t compat_jpeg[] = "jpeg,t8101\0jpeg,s5l8920x";

#define COMPAT(path, bytes) \
    {(path), "compatible", (bytes), (uint32_t)sizeof(bytes)}

static const AppleModernAdtOverride profile_disp0[] = {
    COMPAT("/arm-io/disp0", compat_disp0),
};
static const AppleModernAdtOverride profile_no_dcp[] = {
    COMPAT("/arm-io/disp0", compat_disp0),
    {"/arm-io/disp0", "no-dcp-driver", no_dcp_driver_one,
     (uint32_t)sizeof(no_dcp_driver_one)},
};
static const AppleModernAdtOverride profile_control[] = {
    COMPAT("/arm-io/audio-resource-manager", compat_audio_rm),
    COMPAT("/arm-io/iop-audio-controller", compat_iop_audio),
};
static const AppleModernAdtOverride profile_gate_control[] = {
    COMPAT("/arm-io/jpeg0-h17p", compat_jpeg),
    COMPAT("/arm-io/audio-resource-manager", compat_audio_rm),
};
static const AppleModernAdtOverride profile_dcp_chain[] = {
    COMPAT("/arm-io/disp0", compat_disp0),
    COMPAT("/arm-io/dcp", compat_dcp),
    COMPAT("/arm-io/dcp/iop-dcp-nub", compat_dcp_nub),
    COMPAT("/arm-io/dcp0-expert", compat_dcp_expert),
    COMPAT("/arm-io/dart-dcp", compat_dart),
    {"/arm-io/dart-dcp", "dart-id", dart_id_0, (uint32_t)sizeof(dart_id_0)},
    COMPAT("/arm-io/dart-disp0", compat_dart),
    {"/arm-io/dart-disp0", "dart-id", dart_id_1, (uint32_t)sizeof(dart_id_1)},
};
/*
 * w12-dcp.  dcp-chain plus the one stock "compatible" the mapper NUBS need.
 *
 * MEASURED (w12-dcp runs/R1): under dcp-chain the guest's own IOService plane
 * holds six IODARTMapperNub children of the two AppleT8110DARTs and ZERO
 * IODARTMapper services.  ATTESTED (BootKC __PRELINK_INFO): the only
 * IODARTMapper personality is com.apple.driver.IODARTFamily's, IOProviderClass
 * IODARTMapperNub, IONameMatch "iommu-mapper" - and published XNU matches an
 * IONameMatch token against a DT nub's name, compatible, device_type and model
 * (IODTCompareNubName), none of which is "iommu-mapper" on the served tree,
 * because the served tree strips every mapper node's compatible.  So no
 * IOMapper can ever register, and AppleA7IOP::start - whose blocked frame in
 * w11-clcdstart holds the live DART property string "truncate-dvas" - has
 * nothing to wake it.  Restoring the stock compatible on the three mapper nodes
 * that /arm-io/dcp (iommu-parent = mapper-dcp) and /arm-io/disp0 (iommu-parent
 * = mapper-disp0, mapper-disp0-piodma) name is therefore the cheapest
 * declared, anchored measure that can let the wrapper's mapper wait complete.
 */
static const AppleModernAdtOverride profile_dcp_mapper[] = {
    COMPAT("/arm-io/disp0", compat_disp0),
    COMPAT("/arm-io/dcp", compat_dcp),
    COMPAT("/arm-io/dcp/iop-dcp-nub", compat_dcp_nub),
    COMPAT("/arm-io/dcp0-expert", compat_dcp_expert),
    COMPAT("/arm-io/dart-dcp", compat_dart),
    {"/arm-io/dart-dcp", "dart-id", dart_id_0, (uint32_t)sizeof(dart_id_0)},
    COMPAT("/arm-io/dart-disp0", compat_dart),
    {"/arm-io/dart-disp0", "dart-id", dart_id_1, (uint32_t)sizeof(dart_id_1)},
    COMPAT("/arm-io/dart-dcp/mapper-dcp", compat_iommu_mapper),
    COMPAT("/arm-io/dart-disp0/mapper-disp0", compat_iommu_mapper),
    COMPAT("/arm-io/dart-disp0/mapper-disp0-piodma", compat_iommu_mapper),
};

const AppleModernAdtOverride *apple_modern_disp_probe_profile(const char *name,
                                                              size_t *count)
{
    if (!name || !count) {
        return NULL;
    }
    if (!strcmp(name, APPLE_MODERN_DISP_PROBE_DISP0)) {
        *count = sizeof(profile_disp0) / sizeof(profile_disp0[0]);
        return profile_disp0;
    }
    if (!strcmp(name, APPLE_MODERN_DISP_PROBE_NO_DCP)) {
        *count = sizeof(profile_no_dcp) / sizeof(profile_no_dcp[0]);
        return profile_no_dcp;
    }
    if (!strcmp(name, APPLE_MODERN_DISP_PROBE_CONTROL)) {
        *count = sizeof(profile_control) / sizeof(profile_control[0]);
        return profile_control;
    }
    if (!strcmp(name, APPLE_MODERN_DISP_PROBE_GATE_CONTROL)) {
        *count = sizeof(profile_gate_control) / sizeof(profile_gate_control[0]);
        return profile_gate_control;
    }
    if (!strcmp(name, APPLE_MODERN_DISP_PROBE_DCP_CHAIN)) {
        *count = sizeof(profile_dcp_chain) / sizeof(profile_dcp_chain[0]);
        return profile_dcp_chain;
    }
    if (!strcmp(name, APPLE_MODERN_DISP_PROBE_DCP_MAPPER)) {
        *count = sizeof(profile_dcp_mapper) / sizeof(profile_dcp_mapper[0]);
        return profile_dcp_mapper;
    }
    *count = 0;
    return NULL;
}

bool apple_modern_disp_probe_supplies_dart_id(const char *name)
{
    size_t count = 0;
    const AppleModernAdtOverride *profile =
        apple_modern_disp_probe_profile(name, &count);
    for (size_t i = 0; i < count; i++) {
        if (!strcmp(profile[i].name, "dart-id")) {
            return true;
        }
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

static const char *const node_paths[APPLE_MODERN_DISP_TRACE_NODES] = {
    "/arm-io/disp0", "/arm-io/dcp0-expert", "/arm-io/dcp",
    "/arm-io/dart-dcp", "/arm-io/dart-disp0",
};

const char *apple_modern_disp_trace_node_name(unsigned node)
{
    return node < APPLE_MODERN_DISP_TRACE_NODES ? node_paths[node] : "?";
}

bool apple_modern_disp_trace_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDispTracePlan *output, Error **errp)
{
    AppleModernDispTracePlan plan;
    AppleModernBlob ranges;

    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "disp0 trace output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    memset(&plan, 0, sizeof(plan));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "disp0 trace DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size ||
            exclusions[i].size > UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "disp0 trace exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp) ||
        !ranges.size || ranges.size % 24) {
        if (errp && !*errp) {
            error_setg(errp, "disp0 trace requires /arm-io ranges");
        }
        return false;
    }
    for (unsigned node = 0; node < APPLE_MODERN_DISP_TRACE_NODES; node++) {
        AppleModernBlob reg;
        if (!apple_modern_adt_property(tree, node_paths[node], "reg", &reg, errp) ||
            !reg.size || reg.size % 16) {
            if (errp && !*errp) {
                error_setg(errp, "disp0 trace requires a %s reg property",
                           node_paths[node]);
            }
            return false;
        }
        for (size_t e = 0; e < reg.size / 16; e++) {
            uint64_t bus = little(reg.data + e * 16, 8);
            uint64_t size = little(reg.data + e * 16 + 8, 8);
            uint64_t address = 0;
            unsigned matches = 0, status;

            if (!size || size > UINT64_MAX - bus) {
                error_setg(errp, "%s reg[%zu] is empty or wraps",
                           node_paths[node], e);
                return false;
            }
            for (size_t i = 0; i < ranges.size; i += 24) {
                uint64_t c = little(ranges.data + i, 8);
                uint64_t p = little(ranges.data + i + 8, 8);
                uint64_t n = little(ranges.data + i + 16, 8);
                if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
                    error_setg(errp, "disp0 trace bus range is empty or wraps");
                    return false;
                }
                if (bus >= c && bus - c < n && size <= n - (bus - c)) {
                    address = p + (bus - c);
                    matches++;
                }
            }
            if (matches != 1) {
                error_setg(errp, "%s reg[%zu] is outside /arm-io or ambiguous",
                           node_paths[node], e);
                return false;
            }
            if (plan.count >= APPLE_MODERN_DISP_TRACE_MAX_WINDOWS) {
                error_setg(errp, "disp0 trace has too many candidate windows");
                return false;
            }
            status = APPLE_MODERN_DISP_TRACE_MAPPED;
            if (overlaps(address, size, dram_base, dram_size)) {
                status = APPLE_MODERN_DISP_TRACE_SKIP_DRAM;
            }
            for (size_t i = 0; status == APPLE_MODERN_DISP_TRACE_MAPPED &&
                               i < exclusion_count; i++) {
                if (overlaps(address, size, exclusions[i].physical_address,
                             exclusions[i].size)) {
                    status = APPLE_MODERN_DISP_TRACE_SKIP_DEVICE;
                }
            }
            for (unsigned i = 0; status == APPLE_MODERN_DISP_TRACE_MAPPED &&
                                 i < plan.count; i++) {
                const AppleModernDispTraceWindow *w = &plan.windows[i];
                if (w->status != APPLE_MODERN_DISP_TRACE_MAPPED) {
                    continue;
                }
                if (address >= w->physical_address && size <= w->size &&
                    address - w->physical_address <= w->size - size) {
                    status = APPLE_MODERN_DISP_TRACE_SKIP_CONTAINED;
                } else if (overlaps(address, size, w->physical_address, w->size)) {
                    status = APPLE_MODERN_DISP_TRACE_SKIP_OVERLAP;
                }
            }
            plan.windows[plan.count++] = (AppleModernDispTraceWindow){
                address, size, (uint8_t)node, (uint8_t)e, (uint8_t)status};
            plan.mapped += status == APPLE_MODERN_DISP_TRACE_MAPPED;
        }
    }
    if (!plan.mapped) {
        error_setg(errp, "disp0 trace mapped no window at all");
        return false;
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

void apple_modern_disp_trace_core_reset(AppleModernDispTraceCore *core)
{
    if (core) {
        memset(core, 0, sizeof(*core));
    }
}

bool apple_modern_disp_trace_core_recorded(const AppleModernDispTraceCore *core,
    unsigned window, uint64_t offset, bool write)
{
    if (!core) {
        return false;
    }
    for (unsigned i = 0; i < core->record_count; i++) {
        if (core->records[i].window == window &&
            core->records[i].offset == offset &&
            core->records[i].write == (write ? 1 : 0)) {
            return true;
        }
    }
    return false;
}

static void note(AppleModernDispTraceCore *core, unsigned window,
                 uint64_t offset, unsigned size, bool write)
{
    if (!core || window >= APPLE_MODERN_DISP_TRACE_MAX_WINDOWS || !size ||
        size > 8) {
        return;
    }
    if (!core->first_window) {
        core->first_window = window + 1;
    }
    increment(write ? &core->window_writes[window] : &core->window_reads[window]);
    increment(write ? &core->writes : &core->reads);
    if (apple_modern_disp_trace_core_recorded(core, window, offset, write)) {
        return;
    }
    if (core->record_count >= APPLE_MODERN_DISP_TRACE_RECORDS) {
        increment(&core->dropped);
        return;
    }
    core->records[core->record_count++] = (AppleModernDispTraceRecord){
        offset, (uint8_t)window, (uint8_t)size, write ? 1u : 0u};
#ifndef APPLE_MODERN_LAYOUT_STANDALONE
    warn_report("apple-modern: disp-trace #%u %s window %u offset 0x%" PRIx64
                " size %u", core->record_count, write ? "write" : "read",
                window, offset, size);
#endif
}

void apple_modern_disp_trace_core_read(AppleModernDispTraceCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t *value)
{
    if (value) {
        *value = 0;
    }
    note(core, window, offset, size, false);
}

void apple_modern_disp_trace_core_write(AppleModernDispTraceCore *core,
    unsigned window, uint64_t offset, unsigned size)
{
    note(core, window, offset, size, true);
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct DispTraceView {
    AppleModernDispTraceCore *core;
    unsigned index;
} DispTraceView;

struct AppleModernDispTraceState {
    SysBusDevice parent_obj;
    AppleModernDispTraceCore core;
    AppleModernDispTracePlan plan;
    DispTraceView views[APPLE_MODERN_DISP_TRACE_MAX_WINDOWS];
    MemoryRegion regions[APPLE_MODERN_DISP_TRACE_MAX_WINDOWS];
};

static uint64_t disp_trace_read(void *opaque, hwaddr offset, unsigned size)
{
    DispTraceView *view = opaque;
    uint64_t value = 0;
    apple_modern_disp_trace_core_read(view->core, view->index, offset, size,
                                      &value);
    return value;
}

static void disp_trace_write(void *opaque, hwaddr offset, uint64_t value,
                             unsigned size)
{
    DispTraceView *view = opaque;
    apple_modern_disp_trace_core_write(view->core, view->index, offset, size);
}

static const MemoryRegionOps disp_trace_ops = {
    .read = disp_trace_read, .write = disp_trace_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8, .unaligned = true},
    .impl = {.min_access_size = 1, .max_access_size = 8, .unaligned = true},
};

static void disp_trace_reset(DeviceState *dev)
{
    apple_modern_disp_trace_core_reset(&APPLE_MODERN_DISP_TRACE(dev)->core);
}

static void disp_trace_realize(DeviceState *dev, Error **errp)
{
    AppleModernDispTraceState *s = APPLE_MODERN_DISP_TRACE(dev);
    unsigned region = 0;

    for (unsigned i = 0; i < s->plan.count; i++) {
        const AppleModernDispTraceWindow *w = &s->plan.windows[i];
        char *name;
        if (w->status != APPLE_MODERN_DISP_TRACE_MAPPED) {
            continue;
        }
        if (region >= APPLE_MODERN_DISP_TRACE_MAX_WINDOWS) {
            error_setg(errp, "disp0 trace plan has too many mapped windows");
            return;
        }
        s->views[region] = (DispTraceView){&s->core, region};
        name = g_strdup_printf("apple-modern.disp-trace[%u]", region);
        memory_region_init_io(&s->regions[region], OBJECT(dev), &disp_trace_ops,
                              &s->views[region], name, w->size);
        g_free(name);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[region]);
        region++;
    }
    if (region != s->plan.mapped) {
        error_setg(errp, "disp0 trace plan mapped-window count disagrees");
    }
}

static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernDispTraceCore *core = &APPLE_MODERN_DISP_TRACE(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}

static void get_unsigned(Object *obj, Visitor *v, const char *name, void *opaque,
                         Error **errp)
{
    AppleModernDispTraceCore *core = &APPLE_MODERN_DISP_TRACE(obj)->core;
    uint64_t value = *(unsigned *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}

static const VMStateDescription disp_trace_unmigratable = {
    .name = TYPE_APPLE_MODERN_DISP_TRACE, .unmigratable = 1,
};

static void disp_trace_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = disp_trace_realize;
    dc->vmsd = &disp_trace_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, disp_trace_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDispTraceCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter,
        NULL, NULL, (void *)offsetof(AppleModernDispTraceCore, writes));
    object_class_property_add(oc, "record-count", "uint64", get_unsigned,
        NULL, NULL, (void *)offsetof(AppleModernDispTraceCore, record_count));
    object_class_property_add(oc, "first-window", "uint64", get_unsigned,
        NULL, NULL, (void *)offsetof(AppleModernDispTraceCore, first_window));
}

DeviceState *apple_modern_disp_trace_new(const AppleModernDispTracePlan *plan)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_DISP_TRACE);
    AppleModernDispTraceState *s = APPLE_MODERN_DISP_TRACE(dev);
    if (plan) {
        s->plan = *plan;
    }
    disp_trace_reset(dev);
    return dev;
}

static const TypeInfo disp_trace_type = {
    .name = TYPE_APPLE_MODERN_DISP_TRACE, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernDispTraceState),
    .class_init = disp_trace_class_init,
};
static void register_types(void) { type_register_static(&disp_trace_type); }
type_init(register_types)
#endif
