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
#endif
#include "hw/arm/apple-silicon/modern-dcp-iop.h"

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

#define APPLE_MODERN_DCP_IOP_OVERRIDE_COUNT 2
static const AppleModernAdtOverride
    dcp_iop_flags[APPLE_MODERN_DCP_IOP_OVERRIDE_COUNT] = {
    { "/arm-io/dcp/iop-dcp-nub", "pre-loaded", flag_one, sizeof(flag_one) },
    { "/arm-io/dcp/iop-dcp-nub", "running", flag_one, sizeof(flag_one) },
};

const AppleModernAdtOverride *apple_modern_dcp_iop_overrides(size_t *count)
{
    if (count) {
        *count = APPLE_MODERN_DCP_IOP_OVERRIDE_COUNT;
    }
    return dcp_iop_flags;
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
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_EXPERT_START;
}

bool apple_modern_dcp_iop_mode_has_flags(unsigned mode)
{
    return mode == APPLE_MODERN_DCP_IOP_MODE_V6 ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V4 ||
           mode == APPLE_MODERN_DCP_IOP_MODE_FLAGS_ONLY ||
           mode == APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED;
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
    bool reset_start;
    bool expert_start;
    MemoryRegion expert_control;
    uint32_t expert_control_value;
    uint32_t expert_control_on;
    uint32_t expert_control_off;
};

static void dcp_iop_handle_message(void *opaque, uint8_t ep, uint64_t message)
{
    AppleModernDcpIop *s = opaque;

    s->messages++;
    /*
     * Declared: nothing behind the endpoint is implemented.  The first message
     * is reported once so the frontier is visible; the rest are counted and
     * flagged as unimplemented rather than silently dropped.
     */
    if (s->messages == 1) {
        warn_report("apple-modern: dcp-iop endpoint %s (raw %u) received its "
                    "FIRST guest message 0x%" PRIx64 "; no DCP message "
                    "semantics are implemented and no reply is sent",
                    s->nub_name, s->endpoint_raw, message);
    }
    qemu_log_mask(LOG_UNIMP,
                  "apple-modern dcp-iop: unimplemented message #%" PRIu64
                  " on user endpoint %u (raw %u): 0x%" PRIx64 "\n",
                  s->messages, ep, s->endpoint_raw, message);
}

static void dcp_iop_boot_done(void *opaque)
{
    AppleModernDcpIop *s = opaque;

    s->rollcall_done = true;
    warn_report("apple-modern: dcp-iop RTKit roll-call COMPLETED; the guest "
                "was told about raw endpoint %u, so RTBuddy should publish a "
                "RTBuddyEndpointService nub named \"%s\"",
                s->endpoint_raw, s->nub_name);
}

/*
 * Observability for the one thing the whole arm turns on: whether the guest
 * ever writes CPU_CTRL RUN on the wrapper block.  The a7iop layer calls these
 * from apple_a7iop_cpu_start(), which is reached only from that write, and the
 * RTKit layer then sends its HELLO.  If neither line appears, the guest never
 * started the coprocessor and no endpoint could ever be advertised -- which is
 * a different failure from a handshake that starts and stalls.
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
    s->endpoint_user = plan->endpoint_user;
    s->endpoint_raw = plan->endpoint_raw;
    snprintf(s->nub_name, sizeof(s->nub_name), "%s", plan->nub_name);
    apple_rtkit_init(APPLE_RTKIT(dev), s, plan->role, plan->wrapper_size,
                     version, &dcp_iop_rtkit_ops);
    if (mode == APPLE_MODERN_DCP_IOP_MODE_V6_EXPERT_START) {
        s->expert_control_on = plan->expert_control_on;
        s->expert_control_off = plan->expert_control_off;
        s->expert_control_value = s->expert_control_off;
        memory_region_init_io(&s->expert_control, OBJECT(s),
                               &dcp_expert_control_ops, s,
                               "apple-modern.dcp-expert-control", 4);
        sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->expert_control);
    }
    /*
     * USER-RELATIVE index: the a7iop layer adds EP_USER_START itself.  Never
     * hand-compute the raw number here; the plan carries it only to report it.
     */
    apple_rtkit_register_user_ep(APPLE_RTKIT(dev), plan->endpoint_user, s,
                                 dcp_iop_handle_message);
    return dev;
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
