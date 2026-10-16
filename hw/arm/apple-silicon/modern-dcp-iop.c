/*
 * Declared, default-off RTKit peer for /arm-io/dcp (dcp-iop).  The plan, the
 * two declared ADT flags and the refusals live in the standalone half; the
 * device wrapper around the in-tree a7iop RTKit lives behind
 * APPLE_MODERN_LAYOUT_STANDALONE.  See the header for what is attested, what
 * is analogy and what is declared.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
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
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "hw/qdev-properties.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#include "system/dma.h"
#endif
#include "hw/arm/apple-silicon/modern-dcp-iop.h"
#include "dcp-av-modes.h"

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

/* Declared presence/true values; the ADT override ABI has no zero-length form. */
/* A bounded string length: the POSIX bounded strlen is not in C11 and the
 * standalone core builds as -std=c11. */
static size_t bounded_length(const char *text, size_t limit)
{
    size_t n = 0;
    while (n < limit && text[n]) {
        n++;
    }
    return n;
}

static const uint8_t flag_one[4] = { 1, 0, 0, 0 };
static const uint8_t segment_base_le[8] = {
    0x00, 0x00, 0xf0, 0x0d, 0x03, 0x00, 0x00, 0x00 /* 0x30df00000 */
};
static const uint8_t segment_size_le[8] = {
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00 /* 0x100000 */
};

#define APPLE_MODERN_DCP_IOP_OVERRIDE_COUNT 2
static const AppleModernAdtOverride
    dcp_iop_flags[APPLE_MODERN_DCP_IOP_OVERRIDE_COUNT] = {
    { "/arm-io/dcp/iop-dcp-nub", "pre-loaded", flag_one, sizeof(flag_one) },
    { "/arm-io/dcp/iop-dcp-nub", "running", flag_one, sizeof(flag_one) },
};

#define APPLE_MODERN_DCP_IOP_SEGMENT_OVERRIDE_COUNT 2
static const AppleModernAdtOverride
    dcp_iop_segment_flags[APPLE_MODERN_DCP_IOP_SEGMENT_OVERRIDE_COUNT] = {
    { "/arm-io/dcp/iop-dcp-nub", "region-base",
      segment_base_le, sizeof(segment_base_le) },
    { "/arm-io/dcp/iop-dcp-nub", "region-size",
      segment_size_le, sizeof(segment_size_le) },
};

const AppleModernAdtOverride *apple_modern_dcp_iop_overrides(size_t *count)
{
    if (count) {
        *count = APPLE_MODERN_DCP_IOP_OVERRIDE_COUNT;
    }
    return dcp_iop_flags;
}

const AppleModernAdtOverride *
apple_modern_dcp_iop_segment_overrides(size_t *count)
{
    if (count) {
        *count = APPLE_MODERN_DCP_IOP_SEGMENT_OVERRIDE_COUNT;
    }
    return dcp_iop_segment_flags;
}

bool apple_modern_dcp_iop_mode(const char *name, unsigned *mode)
{
    static const struct { const char *name; unsigned mode; } table[] = {
        { APPLE_MODERN_DCP_IOP_NAME_V6, APPLE_MODERN_DCP_IOP_MODE_V6 },
        { APPLE_MODERN_DCP_IOP_NAME_V4, APPLE_MODERN_DCP_IOP_MODE_V4 },
        { APPLE_MODERN_DCP_IOP_NAME_V6_QUIESCED,
          APPLE_MODERN_DCP_IOP_MODE_V6_QUIESCED },
        { APPLE_MODERN_DCP_IOP_NAME_FLAGS,
          APPLE_MODERN_DCP_IOP_MODE_FLAGS_ONLY },
        { APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED,
          APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED },
        { APPLE_MODERN_DCP_IOP_NAME_V6_PRESTARTED_QUIESCED,
          APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED_QUIESCED },
        { APPLE_MODERN_DCP_IOP_NAME_V6_EXPERT_START,
          APPLE_MODERN_DCP_IOP_MODE_V6_EXPERT_START },
        { APPLE_MODERN_DCP_IOP_NAME_V6_RESUMED,
          APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED },
    };
    if (!name || !mode) {
        return false;
    }
    for (unsigned i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (!strcmp(name, table[i].name)) {
            *mode = table[i].mode;
            return true;
        }
    }
    return false;
}

bool apple_modern_dcp_iop_mode_has_peer(unsigned mode)
{
    return mode == APPLE_MODERN_DCP_IOP_MODE_V6 ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V4 ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_QUIESCED ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED_QUIESCED ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_EXPERT_START ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED;
}

bool apple_modern_dcp_iop_mode_has_flags(unsigned mode)
{
    return mode == APPLE_MODERN_DCP_IOP_MODE_V6 ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V4 ||
           mode == APPLE_MODERN_DCP_IOP_MODE_FLAGS_ONLY ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED;
}

bool apple_modern_dcp_iop_mode_has_segment_map(unsigned mode)
{
    return mode == APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED;
}

bool apple_modern_dcp_iop_endpoint_name(const char *role, unsigned raw,
                                        char *out, size_t out_size,
                                        unsigned *index, Error **errp)
{
    size_t role_length;
    int written;
    unsigned name_index;

    if (!out || !out_size || !index) {
        error_setg(errp, "dcp-iop endpoint-name output is missing");
        return false;
    }
    memset(out, 0, out_size);
    *index = 0;
    if (!role) {
        error_setg(errp, "dcp-iop endpoint-name needs a role");
        return false;
    }
    role_length = bounded_length(role, APPLE_MODERN_DCP_IOP_ROLE_MAX);
    if (!role_length || role_length == APPLE_MODERN_DCP_IOP_ROLE_MAX) {
        error_setg(errp, "dcp-iop role is empty or longer than %u bytes",
                   APPLE_MODERN_DCP_IOP_ROLE_MAX - 1);
        return false;
    }
    for (size_t i = 0; i < role_length; i++) {
        if (role[i] < 0x21 || role[i] > 0x7e) {
            error_setg(errp, "dcp-iop role byte %zu is not printable ASCII", i);
            return false;
        }
    }
    if (raw < APPLE_MODERN_DCP_IOP_EP_USER_START) {
        error_setg(errp, "raw RTKit endpoint %u is an RTKit control channel "
                   "(below %u) and gets no nub", raw,
                   APPLE_MODERN_DCP_IOP_EP_USER_START);
        return false;
    }
    if (raw > 0xff) {
        error_setg(errp, "raw RTKit endpoint %u does not fit one byte", raw);
        return false;
    }
    name_index = raw - APPLE_MODERN_DCP_IOP_EP_NAME_BIAS;
    written = snprintf(out, out_size, "%sEndpoint%u", role, name_index);
    if (written < 0 || (size_t)written >= out_size) {
        error_setg(errp, "dcp-iop endpoint nub name does not fit");
        return false;
    }
    *index = name_index;
    return true;
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

bool apple_modern_dcp_iop_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    unsigned endpoint_raw, AppleModernDcpIopPlan *output, Error **errp)
{
    AppleModernDcpIopPlan plan;
    AppleModernBlob ranges, reg, compatible, role, interrupts, nub;
    uint64_t bus, size, address = 0;
    unsigned matches = 0;
    size_t role_length;

    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp,
                   "dcp-iop output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    memset(&plan, 0, sizeof(plan));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "dcp-iop DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size ||
            exclusions[i].size > UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "dcp-iop exclusion is empty or wraps");
            return false;
        }
    }
    /*
     * Without the restored stock compatible no AppleASCWrapV6 matches
     * /arm-io/dcp, so no AppleA7IOPNub and no RTBuddy exist and this peer would
     * have no counterpart.  Refuse rather than map a silent device.
     */
    if (!apple_modern_adt_property(tree, "/arm-io/dcp", "compatible",
                                   &compatible, errp) ||
        compatible.size != sizeof("iop,ascwrap-v6") ||
        memcmp(compatible.data, "iop,ascwrap-v6", compatible.size)) {
        if (errp && *errp) {
            error_free(*errp);
            *errp = NULL;
        }
        error_setg(errp, "dcp-iop needs /arm-io/dcp compatible "
                         "\"iop,ascwrap-v6\" in the served tree; combine it "
                         "with a disp0-probe arm that restores it");
        return false;
    }
    /*
     * RTBuddy only matches a nub whose compatible is "iop-nub,rtbuddy-v2", and
     * the two declared flags are written to that node, so refuse when the
     * served tree has not had it restored either.
     */
    if (!apple_modern_adt_property(tree, "/arm-io/dcp/iop-dcp-nub",
                                   "compatible", &nub, errp) ||
        nub.size != sizeof("iop-nub,rtbuddy-v2") ||
        memcmp(nub.data, "iop-nub,rtbuddy-v2", nub.size)) {
        if (errp && *errp) {
            error_free(*errp);
            *errp = NULL;
        }
        error_setg(errp, "dcp-iop needs /arm-io/dcp/iop-dcp-nub compatible "
                         "\"iop-nub,rtbuddy-v2\" in the served tree");
        return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io/dcp", "role", &role, errp) ||
        !role.size || role.size > APPLE_MODERN_DCP_IOP_ROLE_MAX) {
        if (errp && !*errp) {
            error_setg(errp, "dcp-iop requires a /arm-io/dcp role of at most "
                             "%u bytes", APPLE_MODERN_DCP_IOP_ROLE_MAX);
        }
        return false;
    }
    role_length = bounded_length((const char *)role.data, role.size);
    if (!role_length || role_length >= role.size ||
        role_length >= APPLE_MODERN_DCP_IOP_ROLE_MAX) {
        error_setg(errp, "/arm-io/dcp role is empty, too long, or not "
                         "NUL-terminated inside its own property");
        return false;
    }
    memcpy(plan.role, role.data, role_length);
    if (!apple_modern_dcp_iop_endpoint_name(plan.role, endpoint_raw,
                                            plan.nub_name,
                                            sizeof(plan.nub_name),
                                            &matches, errp)) {
        return false;
    }
    plan.endpoint_raw = endpoint_raw;
    plan.endpoint_user = endpoint_raw - APPLE_MODERN_DCP_IOP_EP_USER_START;
    matches = 0;
    if (!apple_modern_adt_property(tree, "/arm-io/dcp", "interrupts",
                                   &interrupts, errp) ||
        interrupts.size != APPLE_MODERN_DCP_IOP_IRQS * 4) {
        if (errp && !*errp) {
            error_setg(errp, "dcp-iop requires exactly %u /arm-io/dcp "
                             "interrupts", APPLE_MODERN_DCP_IOP_IRQS);
        }
        return false;
    }
    for (unsigned i = 0; i < APPLE_MODERN_DCP_IOP_IRQS; i++) {
        plan.interrupts[i] = (uint32_t)little(interrupts.data + i * 4, 4);
        if (!plan.interrupts[i]) {
            error_setg(errp, "/arm-io/dcp interrupt %u is zero", i);
            return false;
        }
        for (unsigned j = 0; j < i; j++) {
            if (plan.interrupts[j] == plan.interrupts[i]) {
                error_setg(errp, "/arm-io/dcp interrupts %u and %u are the "
                           "same line", j, i);
                return false;
            }
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp) ||
        !ranges.size || ranges.size % 24) {
        if (errp && !*errp) {
            error_setg(errp, "dcp-iop requires /arm-io ranges");
        }
        return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io/dcp", "reg", &reg, errp) ||
        reg.size < 16 || reg.size % 16) {
        if (errp && !*errp) {
            error_setg(errp, "dcp-iop requires a /arm-io/dcp reg property");
        }
        return false;
    }
    bus = little(reg.data, 8);
    size = little(reg.data + 8, 8);
    if (size != APPLE_MODERN_DCP_IOP_WRAPPER_SIZE) {
        error_setg(errp, "/arm-io/dcp reg[0] size 0x%llx is not the attested "
                   "0x%llx", (unsigned long long)size,
                   (unsigned long long)APPLE_MODERN_DCP_IOP_WRAPPER_SIZE);
        return false;
    }
    if (size > UINT64_MAX - bus) {
        error_setg(errp, "/arm-io/dcp reg[0] wraps");
        return false;
    }
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t c = little(ranges.data + i, 8);
        uint64_t p = little(ranges.data + i + 8, 8);
        uint64_t n = little(ranges.data + i + 16, 8);
        if (!n || n > UINT64_MAX - c || n > UINT64_MAX - p) {
            error_setg(errp, "dcp-iop bus range is empty or wraps");
            return false;
        }
        if (bus >= c && bus - c < n && size <= n - (bus - c)) {
            address = p + (bus - c);
            matches++;
        }
    }
    if (matches != 1) {
        error_setg(errp, "/arm-io/dcp reg[0] is outside /arm-io or ambiguous");
        return false;
    }
    if (overlaps(address, size, dram_base, dram_size)) {
        error_setg(errp, "/arm-io/dcp reg[0] lands in DRAM");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (overlaps(address, size, exclusions[i].physical_address,
                     exclusions[i].size)) {
            error_setg(errp, "/arm-io/dcp reg[0] overlaps an already mapped "
                       "device");
            return false;
        }
    }
    plan.wrapper_address = address;
    plan.wrapper_size = size;
    *output = plan;
    return true;
}

static bool expert_u32(AppleModernBlob tree, const char *name,
                        uint32_t *value, Error **errp)
{
    AppleModernBlob prop;
    if (!apple_modern_adt_property(tree, "/arm-io/dcp0-expert", name,
                                   &prop, errp)) {
        return false;
    }
    if (prop.size != 4) {
        error_setg(errp, "dcp-iop expert %s must be a 4-byte ADT value", name);
        return false;
    }
    *value = (uint32_t)little(prop.data, 4);
    return true;
}

/* Extend an already validated peer plan with the separate expert control.
 * Geometry/value names come from ADT; control-to-peer behavior is declared. */
bool apple_modern_dcp_iop_expert_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDcpIopPlan *plan, Error **errp)
{
    const char *path = "/arm-io/dcp0-expert";
    AppleModernBlob reg, ranges;
    uint32_t index, on, off;
    uint64_t bus, size, address = 0;
    unsigned matches = 0;

    if (!plan || aliases(plan, sizeof(*plan), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(plan, sizeof(*plan), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "dcp-iop expert output aliases input or exclusions "
                         "are invalid");
        return false;
    }
    plan->expert_control_address = 0;
    plan->expert_control_on = 0;
    plan->expert_control_off = 0;
    if (!dram_size || dram_size > UINT64_MAX - dram_base ||
        plan->wrapper_size != APPLE_MODERN_DCP_IOP_WRAPPER_SIZE ||
        plan->wrapper_size > UINT64_MAX - plan->wrapper_address) {
        error_setg(errp, "dcp-iop expert requires valid DRAM and peer extents");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size ||
            exclusions[i].size > UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "dcp-iop expert exclusion is empty or wraps");
            return false;
        }
    }
    if (!expert_u32(tree, "dcp-controls-reg-index", &index, errp) ||
        !expert_u32(tree, "dcp-controls-value-on", &on, errp) ||
        !expert_u32(tree, "dcp-controls-value-off", &off, errp)) {
        return false;
    }
    if (!apple_modern_adt_property(tree, path, "reg", &reg, errp) ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (!reg.size || reg.size % 16 || index >= reg.size / 16 ||
        on != 0x10 || off != 0) {
        error_setg(errp, "dcp-iop expert control needs the measured "
                         "on=0x10/off=0 and a valid ADT reg index");
        return false;
    }
    bus = little(reg.data + index * 16, 8);
    size = little(reg.data + index * 16 + 8, 8);
    if (size != 4 || bus % 4 || size > UINT64_MAX - bus ||
        !ranges.size || ranges.size % 24) {
        error_setg(errp, "dcp-iop expert control must be a translated "
                         "aligned 4-byte ADT window");
        return false;
    }
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t child = little(ranges.data + i, 8);
        uint64_t parent = little(ranges.data + i + 8, 8);
        uint64_t span = little(ranges.data + i + 16, 8);
        if (!span || span > UINT64_MAX - child ||
            span > UINT64_MAX - parent) {
            error_setg(errp, "dcp-iop expert bus range is empty or wraps");
            return false;
        }
        if (bus >= child && bus - child < span &&
            size <= span - (bus - child)) {
            address = parent + (bus - child);
            matches++;
        }
    }
    if (matches != 1) {
        error_setg(errp, "dcp-iop expert control translation is missing "
                         "or ambiguous");
        return false;
    }
    if (!address || address % 4) {
        error_setg(errp, "dcp-iop expert control physical address must be "
                         "nonzero and aligned to 4 bytes");
        return false;
    }
    if (overlaps(address, size, dram_base, dram_size) ||
        overlaps(address, size, plan->wrapper_address, plan->wrapper_size)) {
        error_setg(errp, "dcp-iop expert control overlaps DRAM/wrapper");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (overlaps(address, size, exclusions[i].physical_address,
                     exclusions[i].size)) {
            error_setg(errp, "dcp-iop expert control overlaps another device");
            return false;
        }
    }
    plan->expert_control_address = address;
    plan->expert_control_on = on;
    plan->expert_control_off = off;
    return true;
}

bool apple_modern_dcp_iop_resumed_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernDcpIopPlan *plan, Error **errp)
{
    AppleModernBlob reg, ranges;
    uint64_t bus, size, core_address = 0;
    unsigned matches = 0;

    if (!plan || aliases(plan, sizeof(*plan), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(plan, sizeof(*plan), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "dcp-iop resumed output aliases input or exclusions "
                         "are invalid");
        return false;
    }
    plan->core_address = 0;
    plan->core_size = 0;
    plan->segment_address = 0;
    plan->segment_size = 0;
    if (!apple_modern_dcp_iop_expert_plan_build(tree, dram_base, dram_size,
                                                exclusions, exclusion_count,
                                                plan, errp)) {
        return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io/dcp", "reg", &reg, errp) ||
        reg.size < 32 || reg.size % 16 ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp) ||
        !ranges.size || ranges.size % 24) {
        plan->expert_control_address = 0;
        plan->expert_control_on = 0;
        plan->expert_control_off = 0;
        if (errp && !*errp) {
            error_setg(errp, "dcp-iop resumed requires /arm-io/dcp reg[1]");
        }
        return false;
    }
    bus = little(reg.data + 16, 8);
    size = little(reg.data + 24, 8);
    if (size != APPLE_MODERN_DCP_IOP_CORE_SIZE || size > UINT64_MAX - bus) {
        plan->expert_control_address = 0;
        plan->expert_control_on = 0;
        plan->expert_control_off = 0;
        error_setg(errp, "/arm-io/dcp reg[1] size 0x%llx is not the attested "
                   "0x%llx", (unsigned long long)size,
                   (unsigned long long)APPLE_MODERN_DCP_IOP_CORE_SIZE);
        return false;
    }
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t child = little(ranges.data + i, 8);
        uint64_t parent = little(ranges.data + i + 8, 8);
        uint64_t span = little(ranges.data + i + 16, 8);
        if (bus >= child && bus - child < span &&
            size <= span - (bus - child)) {
            core_address = parent + (bus - child);
            matches++;
        }
    }
    if (matches != 1 ||
        overlaps(core_address, size, dram_base, dram_size) ||
        overlaps(core_address, size, plan->wrapper_address,
                 plan->wrapper_size) ||
        overlaps(core_address, size, plan->expert_control_address, 4) ||
        overlaps(APPLE_MODERN_DCP_IOP_SEGMENT_BASE,
                 APPLE_MODERN_DCP_IOP_SEGMENT_SIZE, dram_base, dram_size) ||
        overlaps(APPLE_MODERN_DCP_IOP_SEGMENT_BASE,
                 APPLE_MODERN_DCP_IOP_SEGMENT_SIZE, plan->wrapper_address,
                 plan->wrapper_size) ||
        overlaps(APPLE_MODERN_DCP_IOP_SEGMENT_BASE,
                 APPLE_MODERN_DCP_IOP_SEGMENT_SIZE,
                 plan->expert_control_address, 4) ||
        overlaps(APPLE_MODERN_DCP_IOP_SEGMENT_BASE,
                 APPLE_MODERN_DCP_IOP_SEGMENT_SIZE, core_address, size)) {
        plan->expert_control_address = 0;
        plan->expert_control_on = 0;
        plan->expert_control_off = 0;
        error_setg(errp, "dcp-iop resumed core/segment window translation or "
                         "overlap failed");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (overlaps(core_address, size, exclusions[i].physical_address,
                     exclusions[i].size) ||
            overlaps(APPLE_MODERN_DCP_IOP_SEGMENT_BASE,
                     APPLE_MODERN_DCP_IOP_SEGMENT_SIZE,
                     exclusions[i].physical_address, exclusions[i].size)) {
            plan->expert_control_address = 0;
            plan->expert_control_on = 0;
            plan->expert_control_off = 0;
            error_setg(errp, "dcp-iop resumed core/segment overlaps another "
                             "device");
            return false;
        }
    }
    plan->core_address = core_address;
    plan->core_size = size;
    plan->segment_address = APPLE_MODERN_DCP_IOP_SEGMENT_BASE;
    plan->segment_size = APPLE_MODERN_DCP_IOP_SEGMENT_SIZE;
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE

struct AppleModernDcpIopClass {
    AppleRTKitClass parent_class;
    ResettablePhases parent_phases;
};

struct AppleModernDcpIop {
    AppleRTKit parent_obj;
    unsigned endpoint_user;
    unsigned endpoint_raw;
    char nub_name[APPLE_MODERN_DCP_IOP_ROLE_MAX + 16];
    uint64_t messages;
    uint64_t cpu_starts;
    uint64_t cpu_wakeups;
    bool rollcall_done;
    bool prestarted;
    bool dual_endpoints;
    bool reset_start;
    bool expert_start;
    MemoryRegion expert_control;
    MemoryRegion core_regs;
    MemoryRegion segment_sram;
    uint32_t expert_control_value;
    uint32_t expert_control_on;
    uint32_t expert_control_off;
    AddressSpace *dcp_dma_as;
    AddressSpace *disp0_dma_as;
    uint64_t scanout_pa;
    uint64_t scanout_size;
    uint32_t next_swap_id;
    uint64_t shmem_dva;
    bool a401_pending;
    uint8_t a401_ep;
    uint8_t pending_rpc_ctx;
    unsigned cb_index;
    unsigned cb_count;
    bool normal_mode_seen;
    /* Display-attach callbacks: '+'-separated tags, NULL = none (see below). */
    char *attach_cbs;
    bool attach_after_a453;
    bool attach_sent;
    struct {
        const char *tag;
        uint32_t in_len;
        uint32_t out_len;
        uint32_t prop_id;
        const char *prop_key;
        uint32_t prop_val32;
        uint64_t prop_val64;
        uint8_t payload[0x1010];
        uint32_t payload_len;
    } active_cbs[16];
};

typedef struct QEMU_PACKED {
    char tag[4];
    uint32_t in_len;
    uint32_t out_len;
} DcpRpcPacketHeader;

typedef struct {
    const char *tag;
    uint32_t in_len;
    uint32_t out_len;
    uint32_t prop_id;
    const char *prop_key;
    uint32_t prop_val32;
    uint64_t prop_val64;
} DcpStartupCb;

static const DcpStartupCb dcp_v6_resumed_startup_cbs[] = {
    { .tag = "D107", .in_len = 0,    .out_len = 4 }, /* create_provider_service */
    { .tag = "D108", .in_len = 0,    .out_len = 4 }, /* create_product_service */
    { .tag = "D109", .in_len = 0,    .out_len = 4 }, /* create_PMU_service */
    { .tag = "D110", .in_len = 0,    .out_len = 4 }, /* create_iomfb_service */
    /* D300: IOMFB::PropRelay::publish(RuntimeProperty id=124 enableNormalMode) */
    { .tag = "D300", .in_len = 0x10, .out_len = 0,
      .prop_id = 124, .prop_val32 = 1, .prop_val64 = 1 },
    /* D104: UnifiedPipeline2::set_boolean_property("NormalModeActive", true) */
    { .tag = "D104", .in_len = 0x44, .out_len = 0,
      .prop_key = "NormalModeActive", .prop_val32 = 1 },
    /* D102: UnifiedPipeline2::set_number_property("color-accuracy-index", 0) */
    { .tag = "D102", .in_len = 0x44, .out_len = 0,
      .prop_key = "color-accuracy-index", .prop_val32 = 0 },
    { .tag = "D000", .in_len = 0,    .out_len = 4 }, /* did_boot_signal */
    { .tag = "D001", .in_len = 0,    .out_len = 4 }, /* did_power_on_signal */
    { .tag = "D120", .in_len = 0,    .out_len = 4 }, /* start_hardware_boot */
};

static AddressSpace *dcp_iop_select_dma_as(AppleModernDcpIop *s, uint64_t dva,
                                           void *buf, size_t len,
                                           const char **which,
                                           uint64_t *resolved_dva)
{
    uint64_t trunc36 = dva & UINT64_C(0xfffffffff);

    if (s->dcp_dma_as &&
        dma_memory_read(s->dcp_dma_as, trunc36, buf, len,
                        MEMTXATTRS_UNSPECIFIED) == MEMTX_OK) {
        *which = "dart-dcp(trunc36)";
        *resolved_dva = trunc36;
        return s->dcp_dma_as;
    }
    *which = "none";
    *resolved_dva = dva;
    return NULL;
}

/*
 * Display-attach callbacks (machine options dcp-attach-cbs and
 * dcp-attach-trigger), default none.  Tags and layouts are recovered from the
 * pinned BootKC a36b9241 (evidence features-20261014/claude-gui/re/README.md):
 * the AP dispatcher at unslid 0xfffffff00a1693ec calls the handler for the
 * record's tag; each handler enforces a minimum in/out length and any non-zero
 * return panics ("callback failed with: 0x%x" @link_protocol_priv.h:994).
 *  - D575 IOMobileFramebufferAP::hotPlug_notify_gated(uint64_t state,
 *    IOMFB_TiledDisplayInfo *, bool): in >= 0x58, out >= 0x4c.  in+0x00 state,
 *    +0x08..+0x52 TiledDisplayInfo, +0x53 bool, +0x54 pointer-null flag.
 *    Sent with state 1 and the TiledDisplayInfo pointer null (its field layout
 *    is not recovered), bool 0.  Pending until a client registers for HPD.
 *  - D600 setSystemConsoleMode_gated(bool): in >= 4, bool in byte 0; sent 0.
 * Antigravity's v17 sent D576/D577/D593/D594 (Mac numbering); in this kernel
 * those are other callbacks (D593 needs 8 bytes and panicked with 4, see
 * claude-gui/v1-fullsystem-1200s), so they are not offered.
 */
static const char *const dcp_attach_tags[] = { "D575", "D600", "MODES" };

static const char *dcp_attach_tag(const char *name)
{
    for (size_t i = 0; i < ARRAY_SIZE(dcp_attach_tags); i++) {
        if (!strcmp(name, dcp_attach_tags[i])) {
            return dcp_attach_tags[i];
        }
    }
    return NULL;
}

bool apple_modern_dcp_iop_attach_valid(const char *list, Error **errp)
{
    g_auto(GStrv) tags = g_strsplit(list, "+", -1);

    if (!tags[0]) {
        error_setg(errp, "dcp-attach-cbs is empty");
        return false;
    }
    for (char **t = tags; *t; t++) {
        if (!dcp_attach_tag(*t)) {
            error_setg(errp, "dcp-attach-cbs: unknown callback '%s' (supported: "
                       "D575+D600+MODES, any subset and order)", *t);
            return false;
        }
    }
    return true;
}

/*
 * Append one DCP->AP property push: D126 setDCPAVPropStart, D127
 * setDCPAVPropChunk, D128 setDCPAVPropEnd.  Tags and record layout recovered
 * from the pinned BootKC a36b9241 (features-20261014/claude-gui): D126 in=4
 * (u32 total_length); D127 in=0x1008 (data[0x1000], then u32 offset, u32 length
 * -- data FIRST, the opposite of the Asahi struct order); D128 in=0x40
 * (char key[0x40], NUL-terminated).  The AP reassembles the chunks into one
 * buffer, runs OSUnserializeXML over it and setProperty(key, dict).  Giving the
 * connector >= 1 non-virtual SDR mode makes nr_modes > 0 so CoreDisplay builds
 * a connected display and mints a real CGDirectDisplayID (the gate behind the
 * nil main-display layout / 0xffffffff display id).
 */
static void dcp_iop_append_prop_push(AppleModernDcpIop *s, const char *key,
                                     const char *blob, uint32_t blob_len)
{
    typeof(s->active_cbs[0]) *cb;

    if (s->cb_count + 3 > ARRAY_SIZE(s->active_cbs) || blob_len > 0x1000) {
        return;
    }
    /* D126 setDCPAVPropStart(uint32 total_length) */
    cb = &s->active_cbs[s->cb_count++];
    memset(cb, 0, sizeof(*cb));
    cb->tag = "D126";
    cb->in_len = 4;
    cb->out_len = 4;
    stl_le_p(cb->payload, blob_len);
    cb->payload_len = 4;
    /* D127 setDCPAVPropChunk: data[0x1000], then u32 offset, u32 length */
    cb = &s->active_cbs[s->cb_count++];
    memset(cb, 0, sizeof(*cb));
    cb->tag = "D127";
    cb->in_len = 0x1008;
    cb->out_len = 4;
    memcpy(cb->payload, blob, blob_len);
    stl_le_p(cb->payload + 0x1000, 0);
    stl_le_p(cb->payload + 0x1004, blob_len);
    cb->payload_len = 0x1008;
    /* D128 setDCPAVPropEnd(char key[0x40]) */
    cb = &s->active_cbs[s->cb_count++];
    memset(cb, 0, sizeof(*cb));
    cb->tag = "D128";
    cb->in_len = 0x40;
    cb->out_len = 4;
    strncpy((char *)cb->payload, key, 0x3f);
    cb->payload_len = 0x40;
}

/* Append the selected attach callbacks to active_cbs, always pushing MODES
 * (TimingElements + DisplayAttributes via D126/D127/D128) BEFORE D575 so that
 * IOMobileFramebufferAP::hotPlug_notify_gated(1) never inspects an empty
 * TimingElements property when D575 fires. */
static void dcp_iop_append_attach_cbs(AppleModernDcpIop *s)
{
    g_auto(GStrv) tags = g_strsplit(s->attach_cbs, "+", -1);

    for (char **t = tags; *t && s->cb_count < ARRAY_SIZE(s->active_cbs); t++) {
        const char *tag = dcp_attach_tag(*t);
        if (!strcmp(tag, "MODES")) {
            /*
             * The AP hands the reassembled buffer to OSUnserializeXML(buf,
             * total_length), whose XML path rejects a buffer whose LAST byte
             * (buf[total_length - 1]) is not NUL.  v9 sent total_length without
             * the terminator and logged "OSUnserializeXML failed" twice, so the
             * length here deliberately includes the trailing NUL.
             */
            dcp_iop_append_prop_push(s, "TimingElements",
                                     dcp_av_timing_xml,
                                     sizeof(dcp_av_timing_xml));
            dcp_iop_append_prop_push(s, "DisplayAttributes",
                                     dcp_av_display_attrs_xml,
                                     sizeof(dcp_av_display_attrs_xml));
            /*
             * ProductAttributes carries the display Name/DeviceName that
             * CoreDisplay maps to kCADisplayName/kCADisplayDeviceName; without
             * it +[CADisplay mainDisplay] keeps no reply dict and the main
             * display is never minted (null id / FBSDisplayLayout timeout).
             */
            dcp_iop_append_prop_push(s, "ProductAttributes",
                                     dcp_av_product_attrs_xml,
                                     sizeof(dcp_av_product_attrs_xml));
        }
    }

    for (char **t = tags; *t && s->cb_count < ARRAY_SIZE(s->active_cbs); t++) {
        const char *tag = dcp_attach_tag(*t);
        typeof(s->active_cbs[0]) *cb;

        if (!strcmp(tag, "MODES")) {
            continue;
        }

        cb = &s->active_cbs[s->cb_count];
        memset(cb, 0, sizeof(*cb));
        cb->tag = tag;
        if (!strcmp(tag, "D575")) {
            cb->in_len = 0x58;
            cb->out_len = 0x4c;
            stq_le_p(cb->payload, 1);   /* HPD state: attached */
            cb->payload[0x53] = 0;      /* bool argument */
            cb->payload[0x54] = 1;      /* TiledDisplayInfo pointer is null */
            cb->payload_len = 0x58;
        } else {
            cb->in_len = 4;             /* D600: console mode off */
            cb->payload_len = 4;
        }
        s->cb_count++;
    }
}

static void dcp_iop_send_next_startup_cb(AppleModernDcpIop *s)
{
    while (s->cb_index < s->cb_count) {
        const char *tag = s->active_cbs[s->cb_index].tag;
        uint32_t in_len = s->active_cbs[s->cb_index].in_len;
        uint32_t out_len = s->active_cbs[s->cb_index].out_len;
        uint32_t prop_id = s->active_cbs[s->cb_index].prop_id;
        const char *prop_key = s->active_cbs[s->cb_index].prop_key;
        uint32_t prop_val32 = s->active_cbs[s->cb_index].prop_val32;
        uint64_t prop_val64 = s->active_cbs[s->cb_index].prop_val64;
        uint64_t raw_cb_dva = s->shmem_dva + 0x60000;
        uint64_t cb_dva = raw_cb_dva;
        const char *which = "none";
        uint8_t pkt_buf[0x1020] = { 0 };
        DcpRpcPacketHeader hdr = {
            .tag = { tag[3], tag[2], tag[1], tag[0] },
            .in_len = in_len,
            .out_len = out_len,
        };
        uint32_t total_len = sizeof(hdr) + in_len + out_len;
        uint8_t probe[4] = { 0 };
        AddressSpace *as = dcp_iop_select_dma_as(s, raw_cb_dva, probe,
                                                 sizeof(probe), &which,
                                                 &cb_dva);
        if (!as || total_len > sizeof(pkt_buf)) {
            warn_report("apple-modern: dcp-iop v6-resumed CB #%u ('%s') DMA "
                        "lookup failed at 0x%" PRIx64,
                        s->cb_index, tag, raw_cb_dva);
            break;
        }
        memcpy(pkt_buf, &hdr, sizeof(hdr));
        if (s->active_cbs[s->cb_index].payload_len > 0) {
            memcpy(pkt_buf + sizeof(hdr),
                   s->active_cbs[s->cb_index].payload,
                   s->active_cbs[s->cb_index].payload_len);
        } else if (prop_key && in_len == 0x44) {
            strncpy((char *)(pkt_buf + sizeof(hdr)), prop_key, 0x3f);
            stl_le_p(pkt_buf + sizeof(hdr) + 0x40, prop_val32);
        } else if (in_len == 0x10) {
            stl_le_p(pkt_buf + sizeof(hdr) + 0x0, prop_id);
            stl_le_p(pkt_buf + sizeof(hdr) + 0x4, prop_val32);
            stq_le_p(pkt_buf + sizeof(hdr) + 0x8, prop_val64);
        }
        if (out_len == 4) {
            stl_le_p(pkt_buf + sizeof(hdr) + in_len, 0xdeadbeefU);
        }
        dma_memory_write(as, cb_dva, pkt_buf, total_len,
                         MEMTXATTRS_UNSPECIFIED);
        warn_report("apple-modern: dcp-iop v6-resumed sending CB #%u tag='%s' "
                    "on %s via %s (ctx=0 off=0x0 len=0x%x)",
                    s->cb_index, tag, s->nub_name, which, total_len);
        apple_rtkit_send_user_msg(APPLE_RTKIT(s), s->a401_ep,
                                  ((uint64_t)total_len << 32) | UINT64_C(2));
        return;
    }

    s->a401_pending = false;
    warn_report("apple-modern: dcp-iop v6-resumed CB sequence "
                "complete; sending ACK for ctx=%u", s->pending_rpc_ctx);
    apple_rtkit_send_user_msg(APPLE_RTKIT(s), s->a401_ep,
                              UINT64_C(2) | (UINT64_C(1) << 6) |
                              ((uint64_t)s->pending_rpc_ctx << 8));
}

static void dcp_iop_handle_v6_resumed_rpc(AppleModernDcpIop *s, uint8_t ep,
                                          unsigned raw, uint64_t message)
{
    uint8_t msg_type = message & 0xf;

    if (msg_type == 0) {
        /* IOMFB_MESSAGE_TYPE_SET_SHMEM: DVA is in bits [63:16]. */
        s->shmem_dva = (message >> 16) & ~UINT64_C(0xffff);
        s->a401_pending = false;
        s->cb_index = 0;
        s->cb_count = 0;
        warn_report("apple-modern: dcp-iop v6-resumed SET_SHMEM on %s "
                    "(user %u, raw %u / 0x%x): msg=0x%" PRIx64
                    " shmem_dva=0x%" PRIx64
                    "; replying INITIALIZED with fw_hash=0x15a5c96b",
                    s->nub_name, (unsigned)ep, raw, raw, message,
                    s->shmem_dva);
        apple_rtkit_send_user_msg(APPLE_RTKIT(s), ep,
                                  UINT64_C(0x000015A5C96B0001));
        return;
    }

    if (msg_type == 2) {
        uint32_t len = (uint32_t)(message >> 32);
        uint16_t off = (uint16_t)((message >> 16) & 0xffff);
        uint8_t ctx = (uint8_t)((message >> 8) & 0xf);
        bool ack = (message & (UINT64_C(1) << 6)) != 0;
        uint32_t chan_off = 0;

        if (ctx == 4 || ctx == 6) {
            chan_off = 0x08000;
        } else if (ctx == 3) {
            chan_off = 0x40000;
        } else if (ctx == 7) {
            chan_off = 0x48000;
        }

        if (ack) {
            uint32_t cb_out = 0;
            const char *which = "none";
            uint64_t cb_dva = 0;
            if (ctx == 0 && s->shmem_dva != 0) {
                dcp_iop_select_dma_as(s, s->shmem_dva + 0x60000 + 12,
                                      &cb_out, sizeof(cb_out), &which,
                                      &cb_dva);
            }
            warn_report("apple-modern: dcp-iop v6-resumed RPC ACK #%" PRIu64
                        " on %s: ctx=%u off=0x%x len=0x%x cb_out=0x%x "
                        "raw_msg=0x%" PRIx64,
                        s->messages, s->nub_name, ctx, off, len, cb_out,
                        message);
            if (ctx == 0 && s->a401_pending) {
                s->cb_index++;
                dcp_iop_send_next_startup_cb(s);
            }
            return;
        }

        if (s->shmem_dva != 0 && len >= sizeof(DcpRpcPacketHeader)) {
            DcpRpcPacketHeader hdr = { 0 };
            const char *which = "none";
            uint64_t raw_pkt_dva = s->shmem_dva + chan_off + off;
            uint64_t pkt_dva = raw_pkt_dva;
            AddressSpace *as = dcp_iop_select_dma_as(s, raw_pkt_dva, &hdr,
                                                     sizeof(hdr), &which,
                                                     &pkt_dva);
            if (as) {
                char tag_str[5];
                uint8_t in_preview[32] = { 0 };
                char hex_preview[65] = { 0 };
                uint32_t preview_len = hdr.in_len < sizeof(in_preview) ?
                                       hdr.in_len : sizeof(in_preview);

                for (int i = 0; i < 4; i++) {
                    char c = hdr.tag[3 - i];
                    tag_str[i] = (c >= 0x20 && c <= 0x7e) ? c : '?';
                }
                tag_str[4] = '\0';

                if (preview_len > 0) {
                    dma_memory_read(as, pkt_dva + sizeof(hdr), in_preview,
                                    preview_len, MEMTXATTRS_UNSPECIFIED);
                    for (uint32_t i = 0; i < preview_len; i++) {
                        snprintf(&hex_preview[i * 2], 3, "%02x", in_preview[i]);
                    }
                }

                warn_report("apple-modern: dcp-iop v6-resumed RPC #%" PRIu64
                            " on %s: ctx=%u off=0x%x len=0x%x via=%s "
                            "tag='%s' in_len=0x%x out_len=0x%x in_hex=%s",
                            s->messages, s->nub_name, ctx, off, len, which,
                            tag_str, hdr.in_len, hdr.out_len, hex_preview);
                warn_report("apple-modern: dcp-iop v6-resumed RPCALL #%" PRIu64
                            " tag='%s' ctx=%u in_len=%u out_len=%u",
                            s->messages, tag_str, ctx, hdr.in_len, hdr.out_len);

                if (!strcmp(tag_str, "A352")) {
                    s->normal_mode_seen = true;
                }

                if (hdr.in_len > sizeof(in_preview) && hdr.in_len <= 0x4000) {
                    uint8_t *full_in = g_malloc0(hdr.in_len);
                    dma_memory_read(as, pkt_dva + sizeof(hdr), full_in,
                                    hdr.in_len, MEMTXATTRS_UNSPECIFIED);
                    for (uint32_t off_w = 0; off_w + 8 <= hdr.in_len; off_w += 8) {
                        uint64_t val = ldq_le_p(full_in + off_w);
                        if (val != 0 && val != UINT64_C(0xaaaaaaaaaaaaaaaa)) {
                            warn_report("apple-modern: dcp-iop v6-resumed RPC #%" PRIu64
                                        " tag='%s' in[+0x%03x]=0x%016" PRIx64,
                                        s->messages, tag_str, off_w, val);
                        }
                        if ((!strcmp(tag_str, "A407") || !strcmp(tag_str, "A408")) &&
                            (val >> 36) == UINT64_C(0x10) &&
                            (val & UINT64_C(0xfffffffff)) != 0 &&
                            s->disp0_dma_as) {
                            const uint32_t fb_bytes = 1024 * 768 * 4;
                            uint64_t surf_dva = val & UINT64_C(0xfffffffff);
                            uint8_t *surf_buf = g_malloc0(fb_bytes);
                            if (dma_memory_read(s->disp0_dma_as, surf_dva,
                                                surf_buf, fb_bytes,
                                                MEMTXATTRS_UNSPECIFIED) ==
                                MEMTX_OK) {
                                uint32_t nonzero_rgb = 0;
                                for (uint32_t px = 0; px < 1024 * 768; px++) {
                                    if ((ldl_le_p(surf_buf + px * 4) &
                                         0x00ffffffu) != 0) {
                                        nonzero_rgb++;
                                    }
                                }
                                warn_report("apple-modern: dcp-iop v6-resumed "
                                            "%s surface at in[+0x%03x] "
                                            "dva=0x%" PRIx64 " via=dart-disp0(trunc36) "
                                            "nonzero_rgb_pixels=%u",
                                            tag_str, off_w, val, nonzero_rgb);
                                if (nonzero_rgb > 0 && s->scanout_pa &&
                                    s->scanout_size >= fb_bytes) {
                                    address_space_write(&address_space_memory,
                                                        s->scanout_pa,
                                                        MEMTXATTRS_UNSPECIFIED,
                                                        surf_buf, fb_bytes);
                                }
                            }
                            g_free(surf_buf);
                        }
                    }
                    g_free(full_in);
                }

                if (hdr.out_len > 0 && hdr.out_len <= 0x4000) {
                    uint64_t out_dva = pkt_dva + sizeof(hdr) + hdr.in_len;
                    uint8_t *zeros = g_malloc0(hdr.out_len);
                    /* Methods returning bool_ true on init/display queries */
                    if (hdr.out_len >= 4 &&
                        (!strcmp(tag_str, "A000") ||
                         !strcmp(tag_str, "A002") ||
                         !strcmp(tag_str, "A020") ||
                         !strcmp(tag_str, "A024") ||
                         !strcmp(tag_str, "A030") ||
                         !strcmp(tag_str, "A031") ||
                         !strcmp(tag_str, "A032") ||
                         !strcmp(tag_str, "A035") ||
                         !strcmp(tag_str, "A036") ||
                         !strcmp(tag_str, "A037") ||
                         !strcmp(tag_str, "A043") ||
                         !strcmp(tag_str, "A115") ||
                         !strcmp(tag_str, "A116") ||
                         !strcmp(tag_str, "A130") ||
                         !strcmp(tag_str, "A131") ||
                         !strcmp(tag_str, "A132") ||
                         !strcmp(tag_str, "A204") ||
                         !strcmp(tag_str, "A352") ||
                         !strcmp(tag_str, "A381") ||
                         !strcmp(tag_str, "A401") ||
                         /*
                          * A410/A411 = is_main_display family. In this BootKC
                          * A410 is in=8/out=4 and A411 is in=4/out=4 (never
                          * in_len==0), so the old "&& hdr.in_len == 0" guard made
                          * both always return false and the single built-in panel
                          * was never reported as the main display. Assert true.
                          */
                         !strcmp(tag_str, "A410") ||
                         !strcmp(tag_str, "A411") ||
                         !strcmp(tag_str, "A454") ||
                         !strcmp(tag_str, "A455") ||
                         !strcmp(tag_str, "A456") ||
                         !strcmp(tag_str, "A463") ||
                         !strcmp(tag_str, "A465") ||
                         !strcmp(tag_str, "A466") ||
                         !strcmp(tag_str, "A468") ||
                         !strcmp(tag_str, "A473") ||
                         !strcmp(tag_str, "A474") ||
                         !strcmp(tag_str, "A475") ||
                         !strcmp(tag_str, "A479") ||
                         !strcmp(tag_str, "A485"))) {
                        zeros[0] = 1;
                    } else if (!strcmp(tag_str, "A353") && hdr.out_len >= 8) {
                        /*
                         * A353 display_healthcheck_rate_ns (in0/out8): the DCP
                         * stub returns a u64 nanosecond period and the kernel
                         * caller does `cbz x0`, skipping the
                         * exclaves_display_healthcheck_rate report when it is
                         * zero -- which left the panel looking unhealthy.
                         * Falling through to the all-zero default was a bug
                         * (Grok catalog emu_status u64_1h_ns; disasm-confirmed by
                         * the dcp-hpd-subscribe RE).  Return 1 hour in ns
                         * (0x34630B8A000).
                         */
                        stl_le_p(zeros, 0x30B8A000u);
                        stl_le_p(zeros + 4, 0x00000346u);
                    } else if (!strcmp(tag_str, "A412") && hdr.out_len >= 4) {
                        /*
                         * A412 get_digital_out_state: in=0/out=4. The single 4-byte
                         * word is an IOReturn status (the state value travels via an
                         * in/out pointer this call site passes NULL and discards).
                         * kIOReturnSuccess = 0; the old value 1 was a non-success code.
                         */
                        stl_le_p(zeros, 0);
                    } else if (!strcmp(tag_str, "A437")) {
                        /*
                         * V14_7+: get_block_dcp -- timing/param/calibration block.
                         * The kernel reduces the reply to a "block present" bool
                         * (out[0] & 1); an all-zero reply makes the DCP firmware
                         * log "ACSS: get_block failed, no calibration data loaded"
                         * so CoreDisplay cannot complete the display.  Report the
                         * block present.  (A real per-selector payload keyed by
                         * in[0:4] is the eventual complete fix; bytes unrecovered.)
                         */
                        warn_report("apple-modern: dcp-iop v6-resumed A437 get_block id=0x%x",
                                    preview_len >= 4 ? ldl_le_p(in_preview) : 0);
                        if (hdr.out_len >= 1) {
                            zeros[0] = 1;
                        }
                    } else if ((!strcmp(tag_str, "A406") ||
                                (!strcmp(tag_str, "A407") && hdr.in_len < 0x80)) &&
                               hdr.out_len >= 8) {
                        /* swap_start(InOutPtr(uint) swap_id, ...) */
                        if (++s->next_swap_id == 0) {
                            s->next_swap_id = 1;
                        }
                        stl_le_p(zeros, s->next_swap_id);
                        stl_le_p(zeros + 4, 0);
                    } else if ((!strcmp(tag_str, "A472") ||
                                !strcmp(tag_str, "A473") ||
                                !strcmp(tag_str, "A468") ||
                                !strcmp(tag_str, "A484")) &&
                               hdr.out_len >= 8 && preview_len >= 4) {
                        /*
                         * setPowerState(ulong powerState, ..., OutPtr(uint) outState, ...)
                         * Echo requested powerState in out[0..3] and return 0 (kIOReturnSuccess).
                         */
                        stl_le_p(zeros, ldl_le_p(in_preview));
                        stl_le_p(zeros + 4, 0);
                    } else if (!strcmp(tag_str, "A453")) {
                        /*
                         * Native A453 in pinned BootKC a36b9241... is:
                         * virtual void IOMobileFramebufferShim::get_display_size(uint32_t*, uint32_t*) const
                         * Output 8 bytes are width (1024) and height (768), with no IOReturn status field.
                         */
                        if (hdr.out_len >= 8) {
                            stl_le_p(zeros, 1024);
                            stl_le_p(zeros + 4, 768);
                        }
                    } else if ((!strcmp(tag_str, "A443") ||
                                !strcmp(tag_str, "A444") ||
                                !strcmp(tag_str, "A445") ||
                                !strcmp(tag_str, "A103")) &&
                               hdr.out_len >= 8) {
                        /* get_display_size / get_config_frame_size */
                        stl_le_p(zeros, 1024);
                        stl_le_p(zeros + 4, 768);
                    } else if ((!strcmp(tag_str, "A441") ||
                                !strcmp(tag_str, "A443") ||
                                !strcmp(tag_str, "A440") ||
                                !strcmp(tag_str, "A451") ||
                                !strcmp(tag_str, "A351") ||
                                (!strcmp(tag_str, "A442") && hdr.out_len == 4 && preview_len == 0)) &&
                               hdr.out_len == 4) {
                        /* display_width() -> uint */
                        stl_le_p(zeros, 1024);
                    } else if ((!strcmp(tag_str, "A442") ||
                                !strcmp(tag_str, "A444") ||
                                !strcmp(tag_str, "A452") ||
                                !strcmp(tag_str, "A350")) &&
                               hdr.out_len == 4) {
                        /* display_height() -> uint */
                        stl_le_p(zeros, 768);
                    }
                    dma_memory_write(as, out_dva, zeros, hdr.out_len,
                                     MEMTXATTRS_UNSPECIFIED);
                    warn_report("apple-modern: dcp-iop v6-resumed RPC #%" PRIu64
                                " tag='%s' replied out_len=0x%x out_hex=%02x%02x%02x%02x%02x%02x%02x%02x",
                                s->messages, tag_str, hdr.out_len,
                                zeros[0], zeros[1], zeros[2], zeros[3],
                                hdr.out_len > 4 ? zeros[4] : 0,
                                hdr.out_len > 5 ? zeros[5] : 0,
                                hdr.out_len > 6 ? zeros[6] : 0,
                                hdr.out_len > 7 ? zeros[7] : 0);
                    g_free(zeros);
                }

                if (s->attach_cbs && !s->attach_sent &&
                    s->normal_mode_seen && !s->a401_pending &&
                    !strcmp(tag_str, "A453")) {
                    memset(s->active_cbs, 0, sizeof(s->active_cbs));
                    s->cb_count = 0;
                    dcp_iop_append_attach_cbs(s);
                    s->attach_sent = true;
                    warn_report("apple-modern: dcp-iop v6-resumed attach callbacks "
                                "[%s] nested in RPC #%" PRIu64 " A453 (after "
                                "NormalModeEnable)", s->attach_cbs, s->messages);
                    s->a401_pending = true;
                    s->a401_ep = ep;
                    s->pending_rpc_ctx = ctx;
                    s->cb_index = 0;
                    dcp_iop_send_next_startup_cb(s);
                    return;
                }

                if (ctx == 2 && !strcmp(tag_str, "A401")) {
                    s->a401_pending = true;
                    s->a401_ep = ep;
                    s->pending_rpc_ctx = ctx;
                    s->cb_index = 0;
                    s->cb_count = ARRAY_SIZE(dcp_v6_resumed_startup_cbs);
                    for (unsigned i = 0; i < s->cb_count; i++) {
                        s->active_cbs[i].tag = dcp_v6_resumed_startup_cbs[i].tag;
                        s->active_cbs[i].in_len = dcp_v6_resumed_startup_cbs[i].in_len;
                        s->active_cbs[i].out_len = dcp_v6_resumed_startup_cbs[i].out_len;
                        s->active_cbs[i].prop_id = dcp_v6_resumed_startup_cbs[i].prop_id;
                        s->active_cbs[i].prop_key = dcp_v6_resumed_startup_cbs[i].prop_key;
                        s->active_cbs[i].prop_val32 = dcp_v6_resumed_startup_cbs[i].prop_val32;
                        s->active_cbs[i].prop_val64 = dcp_v6_resumed_startup_cbs[i].prop_val64;
                    }
                    dcp_iop_send_next_startup_cb(s);
                    return;
                }

                if ((!strcmp(tag_str, "A200") || !strcmp(tag_str, "A201") ||
                     !strcmp(tag_str, "A352")) &&
                    preview_len >= 5 && !s->a401_pending) {
                    uint32_t prop_id = ldl_le_p(in_preview);
                    uint32_t prop_val = (preview_len >= 8) ?
                                        ldl_le_p(in_preview + 4) :
                                        (in_preview[4] ? 1u : 0u);
                    if (!strcmp(tag_str, "A200")) {
                        prop_val = in_preview[4] ? 1u : 0u;
                    }
                    memset(s->active_cbs, 0, sizeof(s->active_cbs));
                    s->active_cbs[0].tag = "D300";
                    s->active_cbs[0].in_len = 0x10;
                    s->active_cbs[0].out_len = 0;
                    s->active_cbs[0].prop_id = prop_id;
                    s->active_cbs[0].prop_val32 = prop_val;
                    s->active_cbs[0].prop_val64 = prop_val;
                    s->cb_count = 1;
                    if (prop_id == 124) {
                        s->active_cbs[1].tag = "D104";
                        s->active_cbs[1].in_len = 0x44;
                        s->active_cbs[1].out_len = 0;
                        s->active_cbs[1].prop_key = "NormalModeActive";
                        s->active_cbs[1].prop_val32 = prop_val ? 1u : 0u;
                        s->cb_count = 2;
                        if (prop_val != 0 && s->attach_cbs &&
                            !s->attach_after_a453) {
                            /* NormalModeEnable = 1: push MODES+D575 now and
                             * leave attach_sent false so the subsequent A453
                             * query also sees a fresh hotplug edge. */
                            dcp_iop_append_attach_cbs(s);
                        }
                    }
                    s->a401_pending = true;
                    s->a401_ep = ep;
                    s->pending_rpc_ctx = ctx;
                    s->cb_index = 0;
                    dcp_iop_send_next_startup_cb(s);
                    return;
                }

                uint64_t ack_msg = UINT64_C(2) | (UINT64_C(1) << 6) |
                                   ((uint64_t)ctx << 8);
                apple_rtkit_send_user_msg(APPLE_RTKIT(s), ep, ack_msg);
                return;
            }
            warn_report("apple-modern: dcp-iop v6-resumed RPC #%" PRIu64
                        " DMA read failed at dva=0x%" PRIx64
                        " (ctx=%u off=0x%x len=0x%x)",
                        s->messages, pkt_dva, ctx, off, len);
        }
    }
}

static void dcp_iop_handle_message(void *opaque, uint8_t ep, uint64_t message)
{
    AppleModernDcpIop *s = opaque;
    unsigned raw = (unsigned)ep + APPLE_MODERN_DCP_IOP_EP_USER_START;

    s->messages++;
    /*
     * Declared: nothing behind the endpoint is implemented in baseline modes.
     * The first message is reported once so the frontier is visible; the rest
     * are counted and flagged as unimplemented rather than silently dropped.
     */
    if (s->messages == 1) {
        warn_report("apple-modern: dcp-iop endpoint %s (user %u, raw %u / 0x%x) "
                    "received its FIRST guest message 0x%" PRIx64 "; no DCP "
                    "message semantics are implemented and no reply is sent",
                    s->nub_name, (unsigned)ep, raw, raw, message);
    }
    if (s->dual_endpoints && raw == s->endpoint_raw) {
        dcp_iop_handle_v6_resumed_rpc(s, ep, raw, message);
    }
    qemu_log_mask(LOG_UNIMP,
                  "apple-modern dcp-iop: unimplemented message #%" PRIu64
                  " on user endpoint %u (raw %u / 0x%x): 0x%" PRIx64 "\n",
                  s->messages, ep, raw, raw, message);
}

static void dcp_iop_boot_done(void *opaque)
{
    AppleModernDcpIop *s = opaque;

    s->rollcall_done = true;
    if (s->dual_endpoints) {
        warn_report("apple-modern: dcp-iop RTKit roll-call COMPLETED; the guest "
                    "was told about raw endpoints %u (0x%x) and %u (0x%x), so "
                    "RTBuddy should publish RTBuddyEndpointService nubs "
                    "including \"%s\"",
                    s->endpoint_raw, s->endpoint_raw,
                    s->endpoint_raw + 1, s->endpoint_raw + 1, s->nub_name);
    } else {
        warn_report("apple-modern: dcp-iop RTKit roll-call COMPLETED; the guest "
                    "was told about raw endpoint %u, so RTBuddy should publish a "
                    "RTBuddyEndpointService nub named \"%s\"",
                    s->endpoint_raw, s->nub_name);
    }
}

/*
 * This witnesses the model's start callback, not necessarily a guest wrapper
 * write. The inherited setter, an RTKit power request, declared reset prestart
 * or declared external expert-control bridge can reach it. Handled MMIO and
 * management trace events distinguish those paths; the start count alone does
 * not show that the guest received HELLO or negotiated any user endpoint.
 */
static void dcp_iop_started(void *opaque)
{
    AppleModernDcpIop *s = opaque;

    s->cpu_starts++;
    warn_report("apple-modern: dcp-iop CPU start #%" PRIu64
                " (%s); RTKit HELLO queued", s->cpu_starts,
                s->reset_start ? "declared reset prestart; no guest write" :
                s->expert_start ? "declared expert-control on-write bridge" :
                                 "CPU_CTRL RUN");
}

static void dcp_iop_woken(void *opaque)
{
    AppleModernDcpIop *s = opaque;

    s->cpu_wakeups++;
    warn_report("apple-modern: dcp-iop the guest woke the coprocessor (wakeup "
                "#%" PRIu64 "); the RTKit HELLO is now in the mailbox",
                s->cpu_wakeups);
}

static const AppleRTKitOps dcp_iop_rtkit_ops = {
    .start = dcp_iop_started,
    .wakeup = dcp_iop_woken,
    .boot_done = dcp_iop_boot_done,
};

uint64_t apple_modern_dcp_iop_messages(DeviceState *dev)
{
    return APPLE_MODERN_DCP_IOP(dev)->messages;
}

bool apple_modern_dcp_iop_rollcall_done(DeviceState *dev)
{
    return APPLE_MODERN_DCP_IOP(dev)->rollcall_done;
}

/* The ADT names the register and on/off values; bridging this external
 * control to our existing RTKit start callback is an explicit opt-in model.
 * Unknown values do not start or stop the peer. No firmware runs. */
static uint64_t dcp_expert_control_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    AppleModernDcpIop *s = opaque;
    qemu_log_mask(LOG_UNIMP, "DCP-EXPERT-CONTROL read offset 0x%" PRIx64
                  " size %u value 0x%x\n", (uint64_t)offset, size,
                  s->expert_control_value);
    return s->expert_control_value;
}

static void dcp_expert_control_write(void *opaque, hwaddr offset,
                                      uint64_t value, unsigned size)
{
    AppleModernDcpIop *s = opaque;
    qemu_log_mask(LOG_UNIMP, "DCP-EXPERT-CONTROL write offset 0x%" PRIx64
                  " size %u value 0x%" PRIx64 "\n", (uint64_t)offset,
                  size, value);
    if (value != s->expert_control_on && value != s->expert_control_off) {
        qemu_log_mask(LOG_UNIMP, "DCP-EXPERT-CONTROL ignored unknown value\n");
        return;
    }
    s->expert_control_value = value;
    s->expert_start = true;
    apple_a7iop_set_cpu_ctrl(APPLE_A7IOP(s),
                            value == s->expert_control_on ? CPU_CTRL_RUN : 0);
    s->expert_start = false;
}

static const MemoryRegionOps dcp_expert_control_ops = {
    .read = dcp_expert_control_read,
    .write = dcp_expert_control_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* Declared ASC core-register window (/arm-io/dcp reg[1]) for v6-resumed:
 * bit 0 at offset 0 mirrors modern-smc's smc_loaded_read (host-simulated
 * firmware-loaded claim for AppleASCWrapV6). */
static uint64_t dcp_core_read(void *opaque, hwaddr offset, unsigned size)
{
    uint64_t val = (offset == 0) ? 1 : 0;
    (void)opaque;
    qemu_log_mask(LOG_UNIMP, "DCP-CORE read offset 0x%" PRIx64
                  " size %u value 0x%" PRIx64 "\n",
                  (uint64_t)offset, size, val);
    return val;
}

static void dcp_core_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    (void)opaque;
    qemu_log_mask(LOG_UNIMP, "DCP-CORE write offset 0x%" PRIx64
                  " size %u value 0x%" PRIx64 "\n",
                  (uint64_t)offset, size, value);
}

static const MemoryRegionOps dcp_core_ops = {
    .read = dcp_core_read,
    .write = dcp_core_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 8 },
};

static uint64_t dcp_segment_read(void *opaque, hwaddr offset, unsigned size)
{
    (void)opaque;
    qemu_log_mask(LOG_UNIMP, "DCP-SEGMENT read offset 0x%" PRIx64 " size %u\n",
                  (uint64_t)offset, size);
    return 0;
}

static void dcp_segment_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size)
{
    (void)opaque;
    qemu_log_mask(LOG_UNIMP, "DCP-SEGMENT write offset 0x%" PRIx64
                  " size %u value 0x%" PRIx64 "\n",
                  (uint64_t)offset, size, value);
}

static const MemoryRegionOps dcp_segment_ops = {
    .read = dcp_segment_read,
    .write = dcp_segment_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

DeviceState *apple_modern_dcp_iop_new(const AppleModernDcpIopPlan *plan,
                                      unsigned mode)
{
    DeviceState *dev;
    AppleModernDcpIop *s;
    AppleA7IOPVersion version;

    assert_nonnull(plan);
    if (!apple_modern_dcp_iop_mode_has_peer(mode)) {
        error_report("apple-modern: dcp-iop mode %u has no peer device", mode);
        exit(EXIT_FAILURE);
    }
    version = mode == APPLE_MODERN_DCP_IOP_MODE_V4 ? APPLE_A7IOP_V4 :
                                                     APPLE_A7IOP_V6;
    dev = qdev_new(TYPE_APPLE_MODERN_DCP_IOP);
    s = APPLE_MODERN_DCP_IOP(dev);
    s->prestarted = mode == APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED ||
                    mode == APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED_QUIESCED;
    s->dual_endpoints = mode == APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED;
    s->endpoint_user = plan->endpoint_user;
    s->endpoint_raw = plan->endpoint_raw;
    snprintf(s->nub_name, sizeof(s->nub_name), "%s", plan->nub_name);
    apple_rtkit_init(APPLE_RTKIT(dev), s, plan->role, plan->wrapper_size,
                     version, &dcp_iop_rtkit_ops);
    if (mode == APPLE_MODERN_DCP_IOP_MODE_V6_EXPERT_START ||
        mode == APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED) {
        s->expert_control_on = plan->expert_control_on;
        s->expert_control_off = plan->expert_control_off;
        s->expert_control_value = s->expert_control_off;
        memory_region_init_io(&s->expert_control, OBJECT(s),
                               &dcp_expert_control_ops, s,
                               "apple-modern.dcp-expert-control", 4);
        sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->expert_control);
    }
    if (mode == APPLE_MODERN_DCP_IOP_MODE_V6_RESUMED) {
        memory_region_init_io(&s->core_regs, OBJECT(s), &dcp_core_ops, s,
                              "apple-modern.dcp-core", plan->core_size);
        sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->core_regs);
        memory_region_init_io(&s->segment_sram, OBJECT(s), &dcp_segment_ops, s,
                              "apple-modern.dcp-segment", plan->segment_size);
        sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->segment_sram);
    }
    /*
     * USER-RELATIVE index: the a7iop layer adds EP_USER_START itself.  Never
     * hand-compute the raw number here; the plan carries it only to report it.
     * In v6-resumed mode, publish both candidate user endpoints (23 -> raw
     * 0x37 and 24 -> raw 0x38) per project-memory/iomfb-pixels-touch-route.md.
     */
    apple_rtkit_register_user_ep(APPLE_RTKIT(dev), plan->endpoint_user, s,
                                 dcp_iop_handle_message);
    if (s->dual_endpoints) {
        apple_rtkit_register_user_ep(APPLE_RTKIT(dev), plan->endpoint_user + 1,
                                     s, dcp_iop_handle_message);
    }
    return dev;
}

void apple_modern_dcp_iop_set_dma(DeviceState *dev, AddressSpace *dcp_dma_as,
                                  AddressSpace *disp0_dma_as)
{
    AppleModernDcpIop *s = APPLE_MODERN_DCP_IOP(dev);
    s->dcp_dma_as = dcp_dma_as;
    s->disp0_dma_as = disp0_dma_as;
}

void apple_modern_dcp_iop_set_attach(DeviceState *dev, const char *cbs,
                                     bool after_a453)
{
    AppleModernDcpIop *s = APPLE_MODERN_DCP_IOP(dev);

    g_free(s->attach_cbs);
    s->attach_cbs = cbs && *cbs ? g_strdup(cbs) : NULL;
    s->attach_after_a453 = after_a453;
}

void apple_modern_dcp_iop_set_scanout(DeviceState *dev, uint64_t scanout_pa,
                                      uint64_t scanout_size)
{
    AppleModernDcpIop *s = APPLE_MODERN_DCP_IOP(dev);
    s->scanout_pa = scanout_pa;
    s->scanout_size = scanout_size;
}

static const VMStateDescription vmstate_apple_modern_dcp_iop = {
    .name = TYPE_APPLE_MODERN_DCP_IOP, .unmigratable = 1,
};

/* Reset all diagnostic witnesses, then prestart only this declared mode after
 * every device's reset hold phase. This mirrors the advertised preloaded/running
 * state without executing firmware. The existing modes remain guest-started. */
static void dcp_iop_reset_hold(Object *obj, ResetType type)
{
    AppleModernDcpIop *s = APPLE_MODERN_DCP_IOP(obj);
    AppleModernDcpIopClass *dc = APPLE_MODERN_DCP_IOP_GET_CLASS(obj);

    if (dc->parent_phases.hold) {
        dc->parent_phases.hold(obj, type);
    }
    /* The inherited A7IOP reset clears status but retains CPU_CTRL. DCP
     * reset must clear RUN before optionally establishing prestarted state. */
    apple_a7iop_set_cpu_ctrl(APPLE_A7IOP(obj), 0);
    s->messages = 0;
    s->cpu_starts = 0;
    s->cpu_wakeups = 0;
    s->rollcall_done = false;
    s->reset_start = false;
    s->expert_start = false;
    s->expert_control_value = s->expert_control_off;
    s->next_swap_id = 0;
    s->shmem_dva = 0;
    s->a401_pending = false;
    s->a401_ep = 0;
    s->cb_index = 0;
    s->normal_mode_seen = false;
    s->attach_sent = false;
}

static void dcp_iop_reset_exit(Object *obj, ResetType type)
{
    AppleModernDcpIop *s = APPLE_MODERN_DCP_IOP(obj);
    AppleModernDcpIopClass *dc = APPLE_MODERN_DCP_IOP_GET_CLASS(obj);

    if (dc->parent_phases.exit) {
        dc->parent_phases.exit(obj, type);
    }
    if (s->prestarted) {
        s->reset_start = true;
        apple_a7iop_set_cpu_ctrl(APPLE_A7IOP(obj), CPU_CTRL_RUN);
        s->reset_start = false;
    }
}

static void apple_modern_dcp_iop_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    AppleModernDcpIopClass *dcp = APPLE_MODERN_DCP_IOP_CLASS(oc);

    resettable_class_set_parent_phases(RESETTABLE_CLASS(oc), NULL,
                                       dcp_iop_reset_hold, dcp_iop_reset_exit,
                                       &dcp->parent_phases);
    dc->desc = "Apple modern DCP RTKit peer (declared, default-off)";
    dc->vmsd = &vmstate_apple_modern_dcp_iop;
    dc->user_creatable = false;
}

static const TypeInfo apple_modern_dcp_iop_info = {
    .name = TYPE_APPLE_MODERN_DCP_IOP,
    .parent = TYPE_APPLE_RTKIT,
    .instance_size = sizeof(AppleModernDcpIop),
    .class_size = sizeof(AppleModernDcpIopClass),
    .class_init = apple_modern_dcp_iop_class_init,
};

static void apple_modern_dcp_iop_register_types(void)
{
    type_register_static(&apple_modern_dcp_iop_info);
}

type_init(apple_modern_dcp_iop_register_types)

#endif /* !APPLE_MODERN_LAYOUT_STANDALONE */
