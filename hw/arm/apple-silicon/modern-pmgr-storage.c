/* Declared PMGR register storage for the registers ApplePMGR::start programs.
 * See the header for what is attested and what is declared.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <inttypes.h>
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
#include "hw/arm/apple-silicon/modern-pmgr-storage.h"

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

#define GROUP_RECORD 36
#define COUNTER_RECORD 64
#define MAX_GROUPS 32
#define MAX_COUNTERS 1024
#define MAX_REG_ENTRIES 64
/* perf-groups word 2 bit 1: ApplePMGR programs this group after initDriver. */
#define GROUP_PROGRAMMED 2

static bool aliases(const void *a, size_t as, const void *b, size_t bs)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return as && bs && (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y ||
                       (x < y + bs && y < x + as));
}

static bool overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    return as && bs && (as > UINT64_MAX - a || bs > UINT64_MAX - b ||
                       (a < b + bs && b < a + as));
}

static uint32_t le32(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
    return le32(p) | (uint64_t)le32(p + 4) << 32;
}

typedef struct Group {
    uint32_t reg_index, base, flags;
    uint32_t end;                                     /* bytes covered, multiple of 4 */
    uint64_t valid[APPLE_MODERN_PMGR_STORAGE_MASKS];
} Group;

static bool translate(AppleModernBlob ranges, uint64_t child, uint64_t size,
                      uint64_t *physical)
{
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t c = le64(ranges.data + i);
        uint64_t p = le64(ranges.data + i + 8);
        uint64_t n = le64(ranges.data + i + 16);
        if (child >= c && child - c <= n && size <= n - (child - c) &&
            p <= UINT64_MAX - (child - c) && p + (child - c) <= UINT64_MAX - size) {
            *physical = p + (child - c);
            return true;
        }
    }
    return false;
}

/* Record one 32-bit register of programmed group g; fail on a malformed record. */
static bool mark(Group *groups, unsigned group_count, AppleModernBlob reg,
                 unsigned group, uint64_t offset, Error **errp)
{
    if (group >= group_count) {
        error_setg(errp, "PMGR perf counter names group %u of %u", group, group_count);
        return false;
    }
    Group *g = &groups[group];
    uint64_t reg_size = le64(reg.data + 16 * g->reg_index + 8);
    if ((offset & 3) || offset > APPLE_MODERN_PMGR_STORAGE_MAX_SPAN - 4 ||
        (uint64_t)g->base + offset > reg_size || reg_size - (g->base + offset) < 4) {
        error_setg(errp, "PMGR perf register +0x%" PRIx64 " of group %u is unaligned, "
                   "too far from the base or outside its reg window", offset, group);
        return false;
    }
    g->valid[offset / 4 / 64] |= UINT64_C(1) << ((offset / 4) % 64);
    if (offset + 4 > g->end) {
        g->end = offset + 4;
    }
    return true;
}

#define ARRAY_ENTRIES(a) (sizeof(a) / sizeof((a)[0]))
#define FIXED_TAG_BASE 0x100

/*
 * Windows whose registers are named by BootKC constants rather than by an ADT
 * table. Each row is a RegMap reg_index (index into /arm-io/pmgr reg), an offset
 * in that window and a byte size; every 4-byte slot is a listed register.
 *  0: NUB_FR_GLOBAL_AP_CONTROLS (reg 4, RegMap selector 66, 0x308004000) +0x8..+0x24:
 *     the AP wake-source mask. AppleT8140PMGR's routine at 0xfffffff009848954
 *     (vtable slot 0x9c8; ApplePMGR's vtable+0x980 routine at 0xfffffff0092a5854
 *     tail-calls it with this+0x6b1c4) checks the requested 8 words against the
 *     supported ones, then writes supported & ~requested to offsets 0x4008 ..
 *     0x4024 (minus 0x4000) through 0xfffffff009848b10. Writes only; no read-back
 *     and no poll. The status words at +0x28..+0x44, read by 0xfffffff009848bb4,
 *     are not listed: nothing on the start path was seen to read them.
 *  1-3: PMS_PTS_PTD (reg 34, RegMap selector 8, 0x3003c0000) +0x18200, +0x18300 and
 *     +0x18400: the PTD interrupt block ApplePMGR configures from _initPMPv2
 *     (0xfffffff00928e304 -> loop at 0xfffffff00928ec40 -> vtable slot 0x950 =
 *     0xfffffff0092bd6f0 -> gated action 0xfffffff0092bd800, opcode 3). Per PTD
 *     entry it does, in this order, a read-modify-write of one vector-config
 *     field (0xfffffff0092e29bc; offset 0x18400 + ((e / 8) * 4 + ((e / 4) & 1) *
 *     0x200) for ptd-driver-version 1, field mask 0x1f at bit 8 * (e % 4); version 0
 *     would use (e / 8) * 4 with 4-bit fields; the ADT carries version 1 on
 *     /arm-io/pmp/iop-pmp-nub, and that the PTD object reads that node was not
 *     verified, so the extent below covers both layouts) and a
 *     write of 1 << (e % 32) to the enable-set bank at 0x18200 + 4 * (e / 32)
 *     (0xfffffff0092e2aec); the matching enable-clear bank is 0x18300 + 4 * (e / 32)
 *     (0xfffffff0092e2b6c). The extents here are the full banks for the 1024
 *     entries of the PTD. ADT /arm-io/aon-ptd names the same bank layout for its own
 *     instance (ptd-int-status-offset 0x0, -enable 0x100, -enable-set 0x200,
 *     -enable-clr 0x300), which is the analogy for reading +0x200 / +0x300 as
 *     write-one-to-set / write-one-to-clear enable banks; this model keeps plain
 *     storage (no W1S/W1C effect, no status) because nothing on this path reads
 *     either bank back. The status bank (+0x18000, read by opcode 5) and the
 *     enable register (+0x18100) are deliberately NOT listed.
 *  4: PMGR_SOC_CLUSTER_CTL (reg 28, RegMap selector 98, 0x300780000; reg 37 repeats the
 *     same range, and /arm-io/mcc reg[0] panic-save is the same physical page, which
 *     no model here owns) +0x0 and +0x4, two registers. ApplePMGR's start calls vtable slot
 *     0x590 (AppleT8140PMGR wrapper 0xfffffff009847d84, then slot 0x9f0) which reaches
 *     the cluster power routine at 0xfffffff009847bf0 with index 0 and enable 1: it
 *     reads the register (readPMGRSOCClusterCtlReg, 0xfffffff0092b09f8), writes it back
 *     with the low nibble set to 0xf ((v & ~0xf) | 0xf), then calls
 *     waitPMGRSOCClusterCtlReg (0xfffffff0092b0adc -> generic wait 0xfffffff0092afba0)
 *     with offset 0, mask 0x10, value 0 and a 1 s timeout: it re-reads the register
 *     until (v & 0x10) == 0, and on timeout panics only if this+0x16d bit 0 is set.
 *     THIS IS A POLL. Zero-reset storage satisfies it on the first read only because
 *     the driver writes just the low nibble and bit 4 never becomes set; real
 *     hardware presumably raises bit 4 while the cluster power transition is pending.
 *     That timing is NOT modelled (declared: the transition completes instantly), and
 *     a driver that ever wrote bit 4 would hang here. The routine is called a second
 *     time with index 1, which does the identical read, write ((v & ~0xf) | 0xf) and
 *     wait at +0x4 (measured as the next frontier after +0x0 alone was listed).
 */
typedef struct FixedWindow {
    unsigned reg_index;
    uint32_t offset, size;
} FixedWindow;
static const FixedWindow fixed_windows[] = {
    {4, 0x8, 0x20},
    {34, 0x18200, 0x80},
    {34, 0x18300, 0x80},
    {34, 0x18400, 0x400},
    {28, 0x0, 0x8},
};

/* Append one window after the geometry checks; *plan is unchanged on failure. */
static bool place(AppleModernPMGRStoragePlan *plan, uint64_t address, uint32_t size,
                  uint32_t tag, const uint64_t *valid, uint64_t dram_base,
                  uint64_t dram_size, const AppleModernAddressRange *exclusions,
                  size_t exclusion_count, Error **errp)
{
    AppleModernPMGRStorageWindow *w;
    if (plan->count == APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS) {
        error_setg(errp, "too many PMGR storage windows");
        return false;
    }
    if (!size || size > APPLE_MODERN_PMGR_STORAGE_MAX_SPAN || address > UINT64_MAX - size ||
        overlaps(address, size, dram_base, dram_size)) {
        error_setg(errp, "PMGR storage window %u is empty, too large, wraps or overlaps DRAM",
                   tag);
        return false;
    }
    for (size_t k = 0; k < exclusion_count; k++) {
        if (overlaps(address, size, exclusions[k].physical_address, exclusions[k].size)) {
            error_setg(errp, "PMGR storage window %u overlaps another device", tag);
            return false;
        }
    }
    for (unsigned k = 0; k < plan->count; k++) {
        if (overlaps(address, size, plan->windows[k].address, plan->windows[k].size)) {
            error_setg(errp, "PMGR storage windows %u and %u overlap",
                       plan->windows[k].group, tag);
            return false;
        }
    }
    w = &plan->windows[plan->count++];
    w->address = address;
    w->size = size;
    w->group = tag;
    memcpy(w->valid, valid, sizeof(w->valid));
    for (unsigned k = 0; k < APPLE_MODERN_PMGR_STORAGE_MASKS; k++) {
        plan->registers += __builtin_popcountll(w->valid[k]);
    }
    return true;
}

bool apple_modern_pmgr_storage_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernPMGRStoragePlan *output, Error **errp)
{
    AppleModernBlob reg, groups_blob, counters, ranges;
    Group groups[MAX_GROUPS];
    AppleModernPMGRStoragePlan plan;
    unsigned group_count, counter_count;
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "PMGR storage output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    memset(&plan, 0, sizeof(plan));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "PMGR storage DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "PMGR storage exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io/pmgr", "reg", &reg, errp) ||
        !apple_modern_adt_property(tree, "/arm-io/pmgr", "perf-groups", &groups_blob, errp) ||
        !apple_modern_adt_property(tree, "/arm-io/pmgr", "perf-counters", &counters, errp) ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (!reg.size || reg.size % 16 || reg.size > MAX_REG_ENTRIES * 16 ||
        !groups_blob.size || groups_blob.size % GROUP_RECORD ||
        groups_blob.size > MAX_GROUPS * GROUP_RECORD ||
        !counters.size || counters.size % COUNTER_RECORD ||
        counters.size > MAX_COUNTERS * COUNTER_RECORD ||
        !ranges.size || ranges.size % 24) {
        error_setg(errp, "unsupported PMGR perf-groups/perf-counters/reg schema");
        return false;
    }
    group_count = groups_blob.size / GROUP_RECORD;
    counter_count = counters.size / COUNTER_RECORD;
    memset(groups, 0, sizeof(groups));
    for (unsigned i = 0; i < group_count; i++) {
        const uint8_t *r = groups_blob.data + GROUP_RECORD * i;
        groups[i].reg_index = le32(r);
        groups[i].base = le32(r + 4);
        groups[i].flags = le32(r + 8);
        if (groups[i].reg_index >= reg.size / 16) {
            error_setg(errp, "PMGR perf group %u names a missing reg window", i);
            return false;
        }
    }
    /* Second loop of the start routine: each programmed group's own register. */
    for (unsigned i = 0; i < group_count; i++) {
        if ((groups[i].flags & GROUP_PROGRAMMED) &&
            !mark(groups, group_count, reg, i, 0, errp)) {
            return false;
        }
    }
    /* First loop: every counter whose group is programmed. */
    for (unsigned i = 0; i < counter_count; i++) {
        const uint8_t *c = counters.data + COUNTER_RECORD * i;
        unsigned type = c[0], group = c[4];
        if (group >= group_count) {
            error_setg(errp, "PMGR perf counter %u names group %u of %u", i, group,
                       group_count);
            return false;
        }
        if (!(groups[group].flags & GROUP_PROGRAMMED)) {
            continue;
        }
        if (type == 3) {
            continue;
        }
        if (type > 4) {
            error_setg(errp, "PMGR perf counter %u has type %u, which panics the driver",
                       i, type);
            return false;
        }
        if (!mark(groups, group_count, reg, group, le32(c + 8), errp)) {
            return false;
        }
        if (type == 1 && (c[1] & 2) &&
            !mark(groups, group_count, reg, c[5], le32(c + 12), errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < group_count; i++) {
        uint64_t base;
        if (!(groups[i].flags & GROUP_PROGRAMMED)) {
            continue;
        }
        if (!translate(ranges, le64(reg.data + 16 * groups[i].reg_index),
                       le64(reg.data + 16 * groups[i].reg_index + 8), &base) ||
            base > UINT64_MAX - groups[i].base) {
            error_setg(errp, "PMGR perf group %u is outside the /arm-io bus ranges", i);
            return false;
        }
        if (!place(&plan, base + groups[i].base, groups[i].end, i, groups[i].valid,
                   dram_base, dram_size, exclusions, exclusion_count, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < ARRAY_ENTRIES(fixed_windows); i++) {
        const FixedWindow *f = &fixed_windows[i];
        uint64_t valid[APPLE_MODERN_PMGR_STORAGE_MASKS] = {0};
        uint64_t base, reg_size;
        if (f->reg_index >= reg.size / 16) {
            error_setg(errp, "PMGR fixed window %u names a missing reg window", i);
            return false;
        }
        reg_size = le64(reg.data + 16 * f->reg_index + 8);
        if (f->offset > reg_size || reg_size - f->offset < f->size ||
            !translate(ranges, le64(reg.data + 16 * f->reg_index), reg_size, &base) ||
            base > UINT64_MAX - f->offset) {
            error_setg(errp, "PMGR fixed window %u is outside its reg window or the "
                       "/arm-io bus ranges", i);
            return false;
        }
        for (unsigned slot = 0; slot < f->size / 4; slot++) {
            valid[slot / 64] |= UINT64_C(1) << (slot % 64);
        }
        if (!place(&plan, base + f->offset, f->size, FIXED_TAG_BASE + i, valid,
                   dram_base, dram_size, exclusions, exclusion_count, errp)) {
            return false;
        }
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

void apple_modern_pmgr_storage_core_reset(AppleModernPMGRStorageCore *core)
{
    memset(core->values, 0, sizeof(core->values));
    memset(core->touched, 0, sizeof(core->touched));
    core->reads = core->writes = 0;
}

static bool slot_valid(const AppleModernPMGRStorageWindow *w, uint64_t slot)
{
    return slot < w->size / 4 && (w->valid[slot / 64] >> (slot % 64)) & 1;
}

/* All covered slots of a natural 4- or 8-byte access are listed registers. */
static bool valid_access(const AppleModernPMGRStorageCore *core, unsigned window,
                         uint64_t offset, unsigned size)
{
    if (window >= core->plan.count || (size != 4 && size != 8) || (offset & (size - 1)) ||
        offset >= core->plan.windows[window].size) {
        return false;
    }
    for (unsigned s = 0; s < size / 4; s++) {
        if (!slot_valid(&core->plan.windows[window], offset / 4 + s)) {
            return false;
        }
    }
    return true;
}

static void touch(AppleModernPMGRStorageCore *core, unsigned window, uint64_t offset,
                  unsigned size)
{
    for (unsigned s = 0; s < size / 4; s++) {
        uint64_t slot = offset / 4 + s;
        core->touched[window][slot / 64] |= UINT64_C(1) << (slot % 64);
    }
}

bool apple_modern_pmgr_storage_core_touched(const AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset)
{
    return core && window < core->plan.count &&
           slot_valid(&core->plan.windows[window], offset / 4) &&
           (core->touched[window][offset / 4 / 64] >> ((offset / 4) % 64)) & 1;
}

bool apple_modern_pmgr_storage_core_read(AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t *value)
{
    if (!core || !value || !valid_access(core, window, offset, size) ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    uint64_t slot = offset / 4;
    *value = core->values[window][slot];
    if (size == 8) {
        *value |= (uint64_t)core->values[window][slot + 1] << 32;
    }
    touch(core, window, offset, size);
    increment(&core->reads);
    return true;
}

bool apple_modern_pmgr_storage_core_write(AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t value)
{
    if (!core || !valid_access(core, window, offset, size)) {
        return false;
    }
    uint64_t slot = offset / 4;
    core->values[window][slot] = (uint32_t)value;
    if (size == 8) {
        core->values[window][slot + 1] = (uint32_t)(value >> 32);
    }
    touch(core, window, offset, size);
    increment(&core->writes);
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct StorageView {
    AppleModernPMGRStorageCore *core;
    unsigned index;
} StorageView;
struct AppleModernPMGRStorageState {
    SysBusDevice parent_obj;
    AppleModernPMGRStorageCore core;
    StorageView views[APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS];
    MemoryRegion regions[APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS];
};
/* A register is announced once, on its first successful access (at most one line
 * per listed register), so a run shows exactly which registers the guest touched. */
static void announce(StorageView *view, bool fresh, hwaddr offset, unsigned size,
                     const char *what)
{
    if (fresh) {
        info_report("apple-modern pmgr-storage: first %s of window %u (group %u) +0x%"
                    HWADDR_PRIx " (%u bytes)", what, view->index,
                    view->core->plan.windows[view->index].group, offset, size);
    }
}
static MemTxResult storage_read(void *opaque, hwaddr offset, uint64_t *value,
                                unsigned size, MemTxAttrs attrs)
{
    StorageView *view = opaque;
    bool fresh = !apple_modern_pmgr_storage_core_touched(view->core, view->index, offset);
    if (!apple_modern_pmgr_storage_core_read(view->core, view->index, offset, size,
                                             value)) {
        return MEMTX_ACCESS_ERROR;
    }
    announce(view, fresh, offset, size, "read");
    return MEMTX_OK;
}
static MemTxResult storage_write(void *opaque, hwaddr offset, uint64_t value,
                                 unsigned size, MemTxAttrs attrs)
{
    StorageView *view = opaque;
    bool fresh = !apple_modern_pmgr_storage_core_touched(view->core, view->index, offset);
    if (!apple_modern_pmgr_storage_core_write(view->core, view->index, offset, size,
                                              value)) {
        return MEMTX_ACCESS_ERROR;
    }
    announce(view, fresh, offset, size, "write");
    return MEMTX_OK;
}
static const MemoryRegionOps storage_ops = {
    .read_with_attrs = storage_read, .write_with_attrs = storage_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 8},
};
static void storage_reset(DeviceState *dev)
{
    apple_modern_pmgr_storage_core_reset(&APPLE_MODERN_PMGR_STORAGE(dev)->core);
}
static void storage_realize(DeviceState *dev, Error **errp)
{
    AppleModernPMGRStorageState *s = APPLE_MODERN_PMGR_STORAGE(dev);
    for (unsigned i = 0; i < s->core.plan.count; i++) {
        char name[48];
        s->views[i] = (StorageView){&s->core, i};
        snprintf(name, sizeof(name), "apple-modern.pmgr-storage-%u",
                 s->core.plan.windows[i].group);
        memory_region_init_io(&s->regions[i], OBJECT(dev), &storage_ops, &s->views[i],
                              name, s->core.plan.windows[i].size);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->regions[i]);
    }
}
static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernPMGRStorageCore *core = &APPLE_MODERN_PMGR_STORAGE(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription storage_unmigratable = {
    .name = TYPE_APPLE_MODERN_PMGR_STORAGE, .unmigratable = 1,
};
static void storage_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = storage_realize;
    dc->vmsd = &storage_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, storage_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernPMGRStorageCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernPMGRStorageCore, writes));
}
DeviceState *apple_modern_pmgr_storage_new(const AppleModernPMGRStoragePlan *plan)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_PMGR_STORAGE);
    APPLE_MODERN_PMGR_STORAGE(dev)->core.plan = *plan;
    storage_reset(dev);
    return dev;
}
static const TypeInfo storage_type = {
    .name = TYPE_APPLE_MODERN_PMGR_STORAGE, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernPMGRStorageState), .class_init = storage_class_init,
};
static void register_types(void) { type_register_static(&storage_type); }
type_init(register_types)
#endif
