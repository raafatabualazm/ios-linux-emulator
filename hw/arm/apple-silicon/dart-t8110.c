/*
 * Apple T8110 DART register and page-table model.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Register/descriptor references (Asahi Linux Contributors):
 * https://github.com/torvalds/linux/blob/master/drivers/iommu/apple-dart.c
 * https://github.com/torvalds/linux/blob/master/drivers/iommu/io-pgtable-dart.c
 * https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/m1n1/hw/dart8110.py
 *
 * Scoped normal DMA model: 16 KiB pages, one TTBR per stream, two or three
 * page-table reads, access permissions, faults, stream gates and invalidation.
 * No DAPF, TZ tagger, diagnostics, performance counters or page-table cache.
 * Capability widths/revision/client count are declared emulation parameters,
 * not measured T8140 register values. Unsupported registers return zero and
 * are counted; writes do not invent behavior. The first fault is retained
 * until W1C and later streams are recorded in ERROR_STREAMS.
 */
#ifndef APPLE_DART_T8110_STANDALONE
#include "qemu/osdep.h"
#else
#include <string.h>
#endif
#include "hw/arm/apple-silicon/dart-t8110.h"

#define BIT32(n) (UINT32_C(1) << (n))
#define ERROR_FLAG BIT32(31)
#define ERROR_CODES UINT32_C(0x7fff)
#define TTBR_ADDRESS UINT32_C(0x3ffffffc)
#define PTE_ADDRESS UINT64_C(0x3ffffffc00)

bool apple_dart_t8110_core_init(AppleDARTT8110Core *s,
                               const AppleDARTT8110Geometry *geometry,
                               const char **reason)
{
    const char *problem = NULL;
    if (!s || !geometry) {
        problem = "missing state or geometry";
    } else if (!geometry->num_streams ||
               geometry->num_streams > APPLE_DART_T8110_STREAMS) {
        problem = "stream count must be from 1 to 256";
    } else if (geometry->va_bits < 32 || geometry->va_bits > 47 ||
               geometry->pa_bits < 32 || geometry->pa_bits > 42) {
        problem = "normal descriptor supports VA widths 32..47 and PA 32..42";
    } else if (geometry->revision != 1 && geometry->revision != 2) {
        problem = "declared revision must be 1 or 2";
    } else if (geometry->revision == 1 && geometry->va_bits > 36) {
        problem = "revision 1 has no four-level translation";
    } else if (geometry->mmio_size < 0x1800 ||
               geometry->mmio_size > 0x400000 ||
               (geometry->mmio_size & 3)) {
        problem = "MMIO span must cover registers and be bounded to 4 MiB";
    }
    if (reason) {
        *reason = problem;
    }
    if (problem) {
        return false;
    }
    memset(s, 0, sizeof(*s));
    s->geometry = *geometry;
    return true;
}

void apple_dart_t8110_core_reset(AppleDARTT8110Core *s)
{
    AppleDARTT8110Geometry geometry = s->geometry;
    memset(s, 0, sizeof(*s));
    s->geometry = geometry;
}

static bool valid_access(const AppleDARTT8110Core *s, uint64_t offset,
                          unsigned size)
{
    return size == 4 && !(offset & 3) && offset < s->geometry.mmio_size;
}

bool apple_dart_t8110_core_read(AppleDARTT8110Core *s, uint64_t offset,
                               unsigned size, uint32_t *value)
{
    unsigned sid;
    if (!value || !valid_access(s, offset, size)) {
        return false;
    }
    s->reads++;
    *value = 0;
    switch (offset) {
    case 0x0:
        *value = 14U << 24;
        return true;
    case 0x4:
        *value = 3; /* full bypass and register protection supported */
        return true;
    case 0x8:
        *value = s->geometry.pa_bits << 24 | s->geometry.va_bits << 16 |
                 s->geometry.revision << 8;
        return true;
    case 0xc:
        *value = s->geometry.num_streams << 16 | s->geometry.num_streams;
        return true;
    case 0x80:
        return true; /* synchronous flush completes before returning */
    case 0x100:
        *value = s->error;
        return true;
    case 0x104:
        *value = s->error_mask;
        return true;
    case 0x170:
        *value = s->error_address;
        return true;
    case 0x174:
        *value = s->error_address >> 32;
        return true;
    case 0x200:
        *value = s->protect;
        return true;
    case 0x204:
        return true; /* write-only clear alias */
    case 0x208:
        *value = s->protect_lock;
        return true;
    }
    if (offset >= 0x1c0 && offset < 0x1e0) {
        *value = s->error_streams[(offset - 0x1c0) / 4];
        return true;
    }
    if ((offset >= 0xc00 && offset < 0xc20) ||
        (offset >= 0xc20 && offset < 0xc40)) {
        /* Declared readback: both set/clear aliases expose current state. */
        *value = s->enabled[(offset & 0x1f) / 4];
        return true;
    }
    if (offset >= 0x1000 && offset < 0x1400) {
        sid = (offset - 0x1000) / 4;
        if (sid < s->geometry.num_streams) {
            *value = s->tcr[sid];
            return true;
        }
    }
    if (offset >= 0x1400 && offset < 0x1800) {
        sid = (offset - 0x1400) / 4;
        if (sid < s->geometry.num_streams) {
            *value = s->ttbr[sid];
            return true;
        }
    }
    s->unknown_reads++;
    return false;
}

bool apple_dart_t8110_core_write(AppleDARTT8110Core *s, uint64_t offset,
                                unsigned size, uint32_t value,
                                AppleDARTT8110Flush *flush)
{
    unsigned sid, bank;
    if (!flush || !valid_access(s, offset, size)) {
        return false;
    }
    *flush = (AppleDARTT8110Flush){ 0 };
    s->writes++;
    switch (offset) {
    case 0x80: {
        unsigned op = (value >> 8) & 7;
        sid = value & 255;
        if (op > 1 || (op == 1 && sid >= s->geometry.num_streams)) {
            s->unknown_writes++;
            return false;
        }
        *flush = (AppleDARTT8110Flush){ true, op == 0, sid };
        s->flushes++;
        return true;
    }
    case 0x100:
        s->error &= ~value;
        return true;
    case 0x104:
        s->error_mask = value;
        return true;
    case 0x200:
        s->protect |= value & 1;
        return true;
    case 0x204:
        s->protect &= ~(value & ~s->protect_lock & 1);
        return true;
    case 0x208:
        s->protect_lock |= value & 1;
        return true;
    }
    if (offset >= 0x1c0 && offset < 0x1e0) {
        s->error_streams[(offset - 0x1c0) / 4] &= ~value;
        return true;
    }
    if ((offset >= 0xc00 && offset < 0xc20) ||
        (offset >= 0xc20 && offset < 0xc40)) {
        bank = (offset & 0x1f) / 4;
        unsigned first_sid = bank * 32;
        uint32_t mask = 0;
        if (first_sid < s->geometry.num_streams) {
            unsigned count = s->geometry.num_streams - first_sid;
            mask = count >= 32 ? UINT32_MAX : (BIT32(count) - 1);
        }
        if (offset < 0xc20) {
            s->enabled[bank] |= value & mask;
        } else {
            s->enabled[bank] &= ~(value & mask);
        }
        /* Flush dependent caches when a stream is disabled. */
        *flush = (AppleDARTT8110Flush){ true, true, 0 };
        return true;
    }
    if (offset >= 0x1000 && offset < 0x1400) {
        sid = (offset - 0x1000) / 4;
        if (sid < s->geometry.num_streams) {
            if (!(s->protect & 1)) {
                s->tcr[sid] = value;
                *flush = (AppleDARTT8110Flush){ true, true, 0 };
            }
            return true;
        }
    }
    if (offset >= 0x1400 && offset < 0x1800) {
        sid = (offset - 0x1400) / 4;
        if (sid < s->geometry.num_streams) {
            if (!(s->protect & 1)) {
                s->ttbr[sid] = value;
                *flush = (AppleDARTT8110Flush){ true, true, 0 };
            }
            return true;
        }
    }
    s->unknown_writes++;
    return false;
}

bool apple_dart_t8110_core_irq(const AppleDARTT8110Core *s)
{
    return (s->error & ERROR_FLAG) && !(s->error_mask & ERROR_FLAG) &&
           (s->error & ERROR_CODES & ~s->error_mask);
}

static bool record_fault(AppleDARTT8110Core *s, unsigned sid, uint64_t iova,
                          unsigned access, uint32_t code)
{
    /* QEMU IOMMU_NONE permission queries are observations, not transactions. */
    if (!access) {
        return false;
    }
    s->faults++;
    if (sid < s->geometry.num_streams) {
        s->error_streams[sid / 32] |= BIT32(sid & 31);
    }
    if (!(s->error & ERROR_FLAG)) {
        s->error = ERROR_FLAG | ((sid & 255) << 20) | code |
                   ((access & APPLE_DART_T8110_WRITE) ? BIT32(28) : 0);
        s->error_address = iova;
    }
    return false;
}

bool apple_dart_t8110_core_translate(AppleDARTT8110Core *s, uint32_t sid,
                                    uint64_t iova, unsigned access,
                                    AppleDARTT8110ReadPTE read_pte,
                                    void *opaque,
                                    AppleDARTT8110Translation *translation)
{
    uint32_t tcr, ttbr;
    uint64_t pa, pte = 0;
    unsigned shifts[] = { 36, 25, 14 };
    unsigned first, page_word, sub_start, sub_end;

    if (!translation) {
        return false;
    }
    *translation = (AppleDARTT8110Translation){
        .mask = APPLE_DART_T8110_PAGE_SIZE - 1,
    };
    s->translations++;
    if (sid >= s->geometry.num_streams ||
        (access & ~(APPLE_DART_T8110_READ | APPLE_DART_T8110_WRITE))) {
        return record_fault(s, sid, iova, access, BIT32(0));
    }
    if (!(s->enabled[sid / 32] & BIT32(sid & 31))) {
        return false; /* disabled stream: no DMA, no fabricated fault */
    }
    tcr = s->tcr[sid];
    if (tcr & BIT32(7)) {
        unsigned mapped_sid = (tcr >> 8) & 15;
        if (mapped_sid >= s->geometry.num_streams) {
            return record_fault(s, sid, iova, access, BIT32(0));
        }
        ttbr = s->ttbr[mapped_sid];
    } else {
        ttbr = s->ttbr[sid];
    }
    if (!(tcr & BIT32(0))) {
        if (tcr & BIT32(1)) {
            if (iova >> s->geometry.pa_bits) {
                return record_fault(s, sid, iova, access, BIT32(6));
            }
            translation->address = iova;
            translation->permissions = APPLE_DART_T8110_READ |
                                       APPLE_DART_T8110_WRITE;
            return true;
        }
        return false; /* TCR zero disables DMA; it is not physical bypass */
    }
    if ((tcr & BIT32(1)) || iova >> s->geometry.va_bits) {
        return record_fault(s, sid, iova, access, BIT32(6));
    }
    first = (tcr & BIT32(3)) ? 0 : 1;
    if ((first == 0 && s->geometry.revision == 1) ||
        (first == 1 && iova >> 36)) {
        return record_fault(s, sid, iova, access, BIT32(6));
    }
    if (!(ttbr & 1)) {
        return record_fault(s, sid, iova, access, BIT32(0));
    }
    pa = (uint64_t)(ttbr & TTBR_ADDRESS) << 12;
    if (pa >> s->geometry.pa_bits) {
        return record_fault(s, sid, iova, access, BIT32(6));
    }
    for (unsigned level = first; level < 3; level++) {
        uint64_t index = (iova >> shifts[level]) & UINT64_C(0x7ff);
        if (!read_pte || !read_pte(opaque, pa + index * 8, &pte)) {
            return record_fault(s, sid, iova, access, BIT32(6));
        }
        if (!(pte & 1)) {
            return record_fault(s, sid, iova, access, BIT32(level + 1));
        }
        pa = (pte & PTE_ADDRESS) << 4;
        if (pa >> s->geometry.pa_bits) {
            return record_fault(s, sid, iova, access, BIT32(6));
        }
    }
    sub_start = (pte >> 52) & 0xfff;
    sub_end = (pte >> 40) & 0xfff;
    page_word = (iova & (APPLE_DART_T8110_PAGE_SIZE - 1)) >> 2;
    if (page_word < sub_start || page_word > sub_end) {
        return record_fault(s, sid, iova, access,
                            (access & APPLE_DART_T8110_WRITE) ?
                            BIT32(4) : BIT32(5));
    }
    translation->permissions = ((pte & BIT32(3)) ? 0 : APPLE_DART_T8110_READ) |
                               ((pte & BIT32(2)) ? 0 : APPLE_DART_T8110_WRITE);
    if ((access & translation->permissions) != access) {
        translation->permissions = 0;
        return record_fault(s, sid, iova, access,
                            (access & APPLE_DART_T8110_WRITE) ?
                            BIT32(4) : BIT32(5));
    }
    translation->address = pa | (iova & (APPLE_DART_T8110_PAGE_SIZE - 1));
    /* Narrow subpage entries to a four-byte cache granule. */
    if (sub_start || sub_end != 0xfff) {
        translation->mask = 3;
    }
    return true;
}

#ifndef APPLE_DART_T8110_STANDALONE
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "system/address-spaces.h"

#define TYPE_APPLE_DART_T8110_IOMMU "apple-dart-t8110-iommu"

typedef struct AppleDARTT8110IOMMU {
    IOMMUMemoryRegion parent;
    AppleDARTT8110State *dart;
    unsigned sid;
} AppleDARTT8110IOMMU;

struct AppleDARTT8110State {
    SysBusDevice parent;
    AppleDARTT8110Core core;
    AppleDARTT8110Geometry geometry;
    MemoryRegion mmio;
    qemu_irq irq;
    AppleDARTT8110IOMMU iommus[APPLE_DART_T8110_STREAMS];
    AddressSpace *dma_as[APPLE_DART_T8110_STREAMS];
    unsigned initialized_streams, traced;
    bool trace;
};

static void t8110_notify(AppleDARTT8110State *s, AppleDARTT8110Flush flush)
{
    IOMMUTLBEvent event = {
        .type = IOMMU_NOTIFIER_UNMAP,
        .entry = {
            .target_as = &address_space_memory,
            .addr_mask = UINT64_MAX,
            .perm = IOMMU_NONE,
        },
    };
    if (flush.valid) {
        for (unsigned i = 0; i < s->initialized_streams; i++) {
            if (flush.all || i == flush.sid ||
                ((s->core.tcr[i] & BIT32(7)) &&
                 ((s->core.tcr[i] >> 8) & 15) == flush.sid)) {
                memory_region_notify_iommu(&s->iommus[i].parent, 0, event);
            }
        }
    }
}

static void t8110_trace(AppleDARTT8110State *s, const char *what,
                        uint64_t offset, uint64_t value, bool known)
{
    if (s->trace && s->traced < 256) {
        s->traced++;
        qemu_log_mask(LOG_UNIMP, "apple-dart-t8110: %s +0x%05" PRIx64
                      " value 0x%" PRIx64 "%s%s\n", what, offset, value,
                      known ? "" : " unsupported",
                      s->traced == 256 ? " (limit)" : "");
    }
}

static uint64_t t8110_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleDARTT8110State *s = opaque;
    uint32_t value = 0;
    bool known = apple_dart_t8110_core_read(&s->core, offset, size, &value);
    t8110_trace(s, "read", offset, value, known);
    return value;
}

static void t8110_write(void *opaque, hwaddr offset, uint64_t value,
                         unsigned size)
{
    AppleDARTT8110State *s = opaque;
    AppleDARTT8110Flush flush = { 0 };
    bool known = apple_dart_t8110_core_write(&s->core, offset, size, value,
                                            &flush);
    t8110_notify(s, flush);
    qemu_set_irq(s->irq, apple_dart_t8110_core_irq(&s->core));
    t8110_trace(s, "write", offset, value, known);
}

static const MemoryRegionOps t8110_ops = {
    .read = t8110_read,
    .write = t8110_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
};

static bool t8110_read_pte(void *opaque, uint64_t address, uint64_t *pte)
{
    MemTxResult result;
    *pte = address_space_ldq(&address_space_memory, address,
                             MEMTXATTRS_UNSPECIFIED, &result);
    return result == MEMTX_OK;
}

static IOMMUTLBEntry t8110_translate(IOMMUMemoryRegion *mr, hwaddr iova,
                                      IOMMUAccessFlags access, int iommu_idx)
{
    AppleDARTT8110IOMMU *iommu = container_of(mr, AppleDARTT8110IOMMU, parent);
    AppleDARTT8110State *s = iommu->dart;
    AppleDARTT8110Translation translation;
    IOMMUTLBEntry entry = {
        .target_as = &address_space_memory,
        .iova = iova & ~(APPLE_DART_T8110_PAGE_SIZE - 1),
        .addr_mask = APPLE_DART_T8110_PAGE_SIZE - 1,
        .perm = IOMMU_NONE,
    };
    bool allowed = apple_dart_t8110_core_translate(&s->core, iommu->sid,
                    iova, access, t8110_read_pte, s, &translation);
    qemu_set_irq(s->irq, apple_dart_t8110_core_irq(&s->core));
    if (allowed) {
        entry.iova = iova & ~translation.mask;
        entry.translated_addr = translation.address & ~translation.mask;
        entry.addr_mask = translation.mask;
        entry.perm = translation.permissions;
    }
    return entry;
}

static uint64_t t8110_min_page_size(IOMMUMemoryRegion *mr)
{
    return 4; /* full pages are 16 KiB; subpage protection needs 4-byte granules */
}

static void t8110_reset(DeviceState *dev)
{
    AppleDARTT8110State *s = APPLE_DART_T8110(dev);
    apple_dart_t8110_core_reset(&s->core);
    t8110_notify(s, (AppleDARTT8110Flush){ true, true, 0 });
    qemu_irq_lower(s->irq);
    s->traced = 0;
}

static void t8110_realize(DeviceState *dev, Error **errp)
{
    AppleDARTT8110State *s = APPLE_DART_T8110(dev);
    const char *reason;
    if (!apple_dart_t8110_core_init(&s->core, &s->geometry, &reason)) {
        error_setg(errp, "apple-dart-t8110: %s", reason);
        return;
    }
    memory_region_set_size(&s->mmio, s->geometry.mmio_size);
    memory_region_set_enabled(&s->mmio, true);
    for (unsigned sid = 0; sid < s->geometry.num_streams; sid++) {
        g_autofree char *name = g_strdup_printf("dart-t8110-stream-%u", sid);
        memory_region_set_size(MEMORY_REGION(&s->iommus[sid]),
                                UINT64_C(1) << s->geometry.va_bits);
        s->dma_as[sid] = g_new0(AddressSpace, 1);
        address_space_init(s->dma_as[sid], MEMORY_REGION(&s->iommus[sid]), name);
        s->initialized_streams++;
    }
}

AddressSpace *apple_dart_t8110_dma_as(AppleDARTT8110State *s, uint32_t sid)
{
    return sid < s->initialized_streams ? s->dma_as[sid] : NULL;
}

static void t8110_init(Object *obj)
{
    AppleDARTT8110State *s = APPLE_DART_T8110(obj);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq);
    /* Keep MemoryRegions for the object's whole lifetime, including re-realize.
     * DMA AddressSpaces are separately allocated and torn down in unrealize.
     */
    memory_region_init_io(&s->mmio, obj, &t8110_ops, s,
                          TYPE_APPLE_DART_T8110, 0x400000);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);
    for (unsigned sid = 0; sid < APPLE_DART_T8110_STREAMS; sid++) {
        g_autofree char *name = g_strdup_printf("dart-t8110-stream-%u", sid);
        memory_region_init_iommu(&s->iommus[sid], sizeof(s->iommus[sid]),
                TYPE_APPLE_DART_T8110_IOMMU, obj, name, UINT64_C(1) << 47);
        /* object_initialize() clears the registered instance, so assign after. */
        s->iommus[sid].sid = sid;
        s->iommus[sid].dart = s;
    }
#define COUNTER(prop, field) object_property_add_uint64_ptr(obj, prop, \
                            &s->core.field, OBJ_PROP_FLAG_READ)
    COUNTER("mmio-reads", reads);
    COUNTER("mmio-writes", writes);
    COUNTER("unknown-reads", unknown_reads);
    COUNTER("unknown-writes", unknown_writes);
    COUNTER("translations", translations);
    COUNTER("faults", faults);
    COUNTER("flushes", flushes);
#undef COUNTER
}

static void t8110_unrealize(DeviceState *dev)
{
    AppleDARTT8110State *s = APPLE_DART_T8110(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    qemu_irq_lower(s->irq);
    memory_region_transaction_begin();
    for (unsigned sid = 0; sid < s->initialized_streams; sid++) {
        /* Defer AS cleanup in its own allocation, never inside freed device
         * storage. Its root references keep all owner/regions alive until RCU
         * readers and callbacks have finished.
         */
        address_space_destroy_free(s->dma_as[sid]);
        s->dma_as[sid] = NULL;
    }
    s->initialized_streams = 0;
    if (sbd->mmio[0].addr != (hwaddr)-1) {
        memory_region_del_subregion(get_system_memory(), &s->mmio);
        sbd->mmio[0].addr = (hwaddr)-1;
    }
    /* AS detachment alone does not dirty QEMU's topology cache. Disable after
     * removing every AS, even when MMIO was never mapped, so final commit
     * rebuilds FlatViews without retaining the departed IOMMU root owners.
     */
    memory_region_set_enabled(&s->mmio, false);
    memory_region_transaction_commit();
}

static const Property t8110_properties[] = {
    DEFINE_PROP_UINT32("num-streams", AppleDARTT8110State,
                       geometry.num_streams, 3),
    DEFINE_PROP_UINT32("va-bits", AppleDARTT8110State, geometry.va_bits, 42),
    DEFINE_PROP_UINT32("pa-bits", AppleDARTT8110State, geometry.pa_bits, 42),
    DEFINE_PROP_UINT32("revision", AppleDARTT8110State, geometry.revision, 2),
    DEFINE_PROP_UINT32("mmio-size", AppleDARTT8110State,
                       geometry.mmio_size, 0x20000),
    DEFINE_PROP_BOOL("trace", AppleDARTT8110State, trace, false),
};

static const VMStateDescription vmstate_t8110 = {
    .name = TYPE_APPLE_DART_T8110,
    .unmigratable = 1,
};

static void t8110_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = t8110_realize;
    dc->unrealize = t8110_unrealize;
    device_class_set_legacy_reset(dc, t8110_reset);
    device_class_set_props(dc, t8110_properties);
    dc->vmsd = &vmstate_t8110;
    dc->desc = "Scoped T8110 DART normal DMA model";
}

static void t8110_iommu_class_init(ObjectClass *klass, const void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);
    imrc->translate = t8110_translate;
    imrc->get_min_page_size = t8110_min_page_size;
}

static const TypeInfo t8110_types[] = {
    {
        .name = TYPE_APPLE_DART_T8110,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(AppleDARTT8110State),
        .instance_init = t8110_init,
        .class_init = t8110_class_init,
    }, {
        .name = TYPE_APPLE_DART_T8110_IOMMU,
        .parent = TYPE_IOMMU_MEMORY_REGION,
        .instance_size = sizeof(AppleDARTT8110IOMMU),
        .class_init = t8110_iommu_class_init,
    },
};

DEFINE_TYPES(t8110_types)
#endif
