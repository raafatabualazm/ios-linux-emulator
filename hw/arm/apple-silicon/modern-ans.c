/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Default-off ANS platform/NVMMU adapter. Public register/TCB precedents:
 * AsahiLinux/m1n1 src/nvme.c; Linux drivers/nvme/host/apple.c.
 * A firmware-free RTKit peer gates readiness on protocol negotiation. This
 * models block I/O, not the ANS CPU, CoastGuard security policy, or SEP keys.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/arm/apple-silicon/modern-ans.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#include "hw/nvme/nvme.h"
#include "hw/irq.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_host.h"
#include "migration/vmstate.h"
#include "system/address-spaces.h"

#define ANS_BAR_SIZE 0x60000
#define ANS_SECURE_SIZE 0x10000
#define ANS_TCB_NUM 0x28100
#define ANS_TCB_ASQ 0x28108
#define ANS_TCB_IOSQ 0x28110
#define ANS_TCB_INVAL 0x28118
#define ANS_TCB_STAT 0x28120
#define ANS_LINEAR_CTRL 0x24908
#define ANS_ADMIN_DB 0x2490c
#define ANS_IO_DB 0x24910
#define ANS_BOOT_STATUS 0x1300
#define ANS_BOOT_OK 0xde71ce55
#define ANS_MAX_TAGS 64

typedef struct AppleModernANS {
    PCIHostState parent_obj;
    AppleRTKit *rtkit;
    NvmeCtrl *nvme;
    PCIBus *bus;
    MemoryRegion bar, secure, nvme_alias, pci_mem, pci_io;
    MemoryRegion dma_root, dma_ram;
    AddressSpace dma_as;
    qemu_irq irq;
    uint64_t ram_base, ram_size, tcb_base[2], occupied;
    uint32_t num_tcbs, linear, inval_status;
    bool negotiated;
    uint64_t reads, writes, submissions, rejected, crypto_rejected;
} AppleModernANS;
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernANS, APPLE_MODERN_ANS)

static bool ans_ram_range(AppleModernANS *s, uint64_t pa, uint64_t size)
{
    return size && pa >= s->ram_base && pa - s->ram_base < s->ram_size &&
           size <= s->ram_size - (pa - s->ram_base);
}

static AddressSpace *ans_dma_space(PCIBus *bus, void *opaque, int devfn)
{
    return &((AppleModernANS *)opaque)->dma_as;
}
static const PCIIOMMUOps ans_iommu_ops = { .get_address_space = ans_dma_space };

static void ans_irq(void *opaque, int irq, int level)
{
    qemu_set_irq(((AppleModernANS *)opaque)->irq, level);
}
static int ans_irq_map(PCIDevice *dev, int pin) { return 0; }

static void ans_protocol_started(void *opaque)
{
    AppleModernANS *s = opaque;
    s->negotiated = false;
}
static void ans_protocol_done(void *opaque)
{
    AppleModernANS *s = opaque;
    s->negotiated = true;
    pci_default_write_config(PCI_DEVICE(s->nvme), PCI_COMMAND,
                             PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER, 2);
}
static const AppleRTKitOps ans_rtkit_ops = {
    .start = ans_protocol_started,
    .wakeup = ans_protocol_started,
    .boot_done = ans_protocol_done,
};

static bool ans_read_ram(AppleModernANS *s, uint64_t pa, void *out, size_t len)
{
    return ans_ram_range(s, pa, len) &&
           address_space_read(&s->dma_as, pa, MEMTXATTRS_UNSPECIFIED,
                              out, len) == MEMTX_OK;
}

static bool ans_prps_valid(AppleModernANS *s, const NvmeCmd *cmd, uint64_t length)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint64_t first = MIN(length, 4096 - (prp1 & 4095));
    uint64_t list[256];
    unsigned count;

    if (!length) {
        return !prp1 && !prp2;
    }
    if (length > (1u << 20) || (prp1 & 3) ||
        !ans_ram_range(s, prp1, first)) {
        return false;
    }
    length -= first;
    if (!length) {
        return true;
    }
    if (length <= 4096) {
        return !(prp2 & 4095) && ans_ram_range(s, prp2, length);
    }
    count = DIV_ROUND_UP(length, 4096);
    if (count > ARRAY_SIZE(list) || (prp2 & 7) ||
        count * 8 > 4096 - (prp2 & 4095) ||
        !ans_read_ram(s, prp2, list, count * 8)) {
        return false;
    }
    for (unsigned i = 0; i < count; i++) {
        uint64_t pa = le64_to_cpu(list[i]);
        uint64_t size = MIN(length, 4096);
        if ((pa & 4095) || !ans_ram_range(s, pa, size)) {
            return false;
        }
        length -= size;
    }
    return true;
}

static bool ans_dma_valid(AppleModernANS *s, unsigned qid, const NvmeCmd *cmd)
{
    uint64_t length = 0;
    if (qid) {
        if (cmd->opcode == NVME_CMD_READ || cmd->opcode == NVME_CMD_WRITE) {
            length = ((le32_to_cpu(cmd->cdw12) & 0xffff) + 1ULL) * 4096;
        }
    } else {
        switch (cmd->opcode) {
        case NVME_ADM_CMD_CREATE_CQ:
        case NVME_ADM_CMD_CREATE_SQ: {
            unsigned entries = (le32_to_cpu(cmd->cdw10) >> 16) + 1;
            length = entries * (cmd->opcode == NVME_ADM_CMD_CREATE_CQ ? 16 : 64);
            return entries <= ANS_MAX_TAGS &&
                   ans_ram_range(s, le64_to_cpu(cmd->dptr.prp1), length);
        }
        case NVME_ADM_CMD_IDENTIFY:
            length = 4096;
            break;
        case NVME_ADM_CMD_GET_LOG_PAGE:
            length = ((((uint64_t)le32_to_cpu(cmd->cdw11) & 0xffff) << 16) |
                      (le32_to_cpu(cmd->cdw10) >> 16)) + 1;
            length *= 4;
            break;
        case NVME_ADM_CMD_DELETE_SQ:
        case NVME_ADM_CMD_DELETE_CQ:
        case NVME_ADM_CMD_GET_FEATURES:
        case NVME_ADM_CMD_SET_FEATURES:
        case NVME_ADM_CMD_ABORT:
            break;
        default:
            return false; /* No unchecked vendor/metadata DMA fallback. */
        }
    }
    return ans_prps_valid(s, cmd, length);
}

static void ans_submit(AppleModernANS *s, unsigned qid, uint32_t tag)
{
    NvmeCmd cmd;
    uint8_t tcb[128];
    uint16_t error = 0;
    uint64_t sq_base;

    if (!s->negotiated || !(s->linear & 1) || tag >= ANS_MAX_TAGS ||
        tag > s->num_tcbs || !s->nvme->sq[qid] ||
        (s->occupied & BIT_ULL(tag))) {
        s->rejected++;
        return;
    }
    sq_base = s->nvme->sq[qid]->dma_addr;
    if (!ans_ram_range(s, sq_base, ANS_MAX_TAGS * sizeof(cmd)) ||
        !ans_ram_range(s, s->tcb_base[qid], ANS_MAX_TAGS * sizeof(tcb)) ||
        !ans_read_ram(s, sq_base + tag * sizeof(cmd), &cmd, sizeof(cmd))) {
        s->rejected++;
        return;
    }
    if (le16_to_cpu(cmd.cid) != tag) {
        s->rejected++;
        return;
    }
    if (!ans_read_ram(s, s->tcb_base[qid] + tag * sizeof(tcb), tcb, sizeof(tcb))) {
        s->rejected++;
        return;
    }
    /* SPTM may supply shadow PRP lists. The TCB PRPs are authoritative, so
     * do not require their list pointer to equal XNU's untrusted SQE pointer.
     * Metadata, SGL and crypto fields are unsupported in this first slice. */
    if (tcb[0] || tcb[2] != tag || tcb[3] || (tcb[1] & ~3) ||
        cmd.flags || cmd.mptr) {
        error = NVME_INVALID_FIELD | NVME_DNR;
    }
    for (unsigned i = 40; i < sizeof(tcb); i++) {
        if (tcb[i]) {
            error = NVME_INVALID_FIELD | NVME_DNR;
            s->crypto_rejected++;
            break;
        }
    }
    if (qid && cmd.opcode != NVME_CMD_READ && cmd.opcode != NVME_CMD_WRITE &&
        cmd.opcode != NVME_CMD_FLUSH) {
        error = NVME_INVALID_OPCODE | NVME_DNR;
    }
    if (qid && (cmd.opcode == NVME_CMD_READ || cmd.opcode == NVME_CMD_WRITE)) {
        NvmeNamespace *ns = nvme_ns(s->nvme, le32_to_cpu(cmd.nsid));
        if ((ns && ns->lbasz != 4096) ||
            ldl_le_p(tcb + 4) != (le32_to_cpu(cmd.cdw12) & 0xffff)) {
            error = NVME_INVALID_FIELD | NVME_DNR;
        }
    }
    if (ldq_le_p(tcb + 24)) {
        unsigned direction = cmd.opcode & 1 ? 2 : 1;
        if (tcb[1] != direction) {
            error = NVME_INVALID_FIELD | NVME_DNR;
        }
    } else if (tcb[1]) {
        error = NVME_INVALID_FIELD | NVME_DNR;
    }
    cmd.dptr.prp1 = cpu_to_le64(ldq_le_p(tcb + 24));
    cmd.dptr.prp2 = cpu_to_le64(ldq_le_p(tcb + 32));
    if (!ans_dma_valid(s, qid, &cmd)) {
        error = NVME_INVALID_FIELD | NVME_DNR;
    }
    if (nvme_apple_submit_cmd(s->nvme, qid, &cmd, error)) {
        s->occupied |= BIT_ULL(tag);
        s->submissions++;
        if (error) {
            s->rejected++;
        }
    } else {
        s->rejected++;
    }
}

static uint64_t ans_bar_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleModernANS *s = opaque;
    uint64_t result;
    s->reads++;
    /* Packed teardown status table used by SPTM: four five-bit fields/word.
     * Busy=1 is this model's explicit profile; no command may appear idle
     * while block I/O or its unposted completion still owns guest DMA. */
    if (offset >= 0x28000 && offset < 0x28040 && size == 4 && !(offset & 3)) {
        result = 0;
        for (unsigned i = 0; i < 4; i++) {
            unsigned tag = ((offset - 0x28000) / 4) * 4 + i;
            if (nvme_apple_cmd_pending(s->nvme, tag)) {
                result |= 1u << (5 * i);
            }
        }
        return result;
    }
    if (offset == ANS_BOOT_STATUS && size == 4) {
        return s->negotiated ? ANS_BOOT_OK : 0;
    }
    if (offset == ANS_LINEAR_CTRL && size == 4) {
        return s->linear;
    }
    if (offset == ANS_TCB_NUM && size == 4) {
        return s->num_tcbs;
    }
    if ((offset == ANS_TCB_STAT || offset == 0x29120) && size == 4) {
        return s->inval_status;
    }
    for (unsigned qid = 0; qid < 2; qid++) {
        uint64_t base = qid ? ANS_TCB_IOSQ : ANS_TCB_ASQ;
        if (offset == base || (offset == base + 4 && size == 4)) {
            result = s->tcb_base[qid] >> ((offset - base) * 8);
            return size == 4 ? (uint32_t)result : result;
        }
    }
    if (offset == 0x1210 && size == 4) {
        return (ANS_MAX_TAGS << 16) | ANS_MAX_TAGS;
    }
    qemu_log_mask(LOG_UNIMP, "modern-ans: unsupported read @0x%"HWADDR_PRIx"\n", offset);
    return 0;
}

static void ans_bar_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    AppleModernANS *s = opaque;
    s->writes++;
    if (offset == ANS_LINEAR_CTRL && size == 4) {
        s->linear = value & 1;
        return;
    }
    if (offset == ANS_TCB_NUM && size == 4 && value < ANS_MAX_TAGS) {
        s->num_tcbs = value;
        return;
    }
    for (unsigned qid = 0; qid < 2; qid++) {
        uint64_t base = qid ? ANS_TCB_IOSQ : ANS_TCB_ASQ;
        if (offset == base && size == 8) {
            s->tcb_base[qid] = value;
            return;
        }
        if ((offset == base || offset == base + 4) && size == 4) {
            unsigned shift = (offset - base) * 8;
            s->tcb_base[qid] = (s->tcb_base[qid] & ~(0xffffffffULL << shift)) |
                                (value << shift);
            return;
        }
    }
    if ((offset == ANS_ADMIN_DB || offset == ANS_IO_DB) && size == 4) {
        ans_submit(s, offset == ANS_IO_DB, value);
        return;
    }
    if (offset == ANS_TCB_INVAL && size == 4) {
        s->inval_status = value >= ANS_MAX_TAGS ||
                          nvme_apple_cmd_pending(s->nvme, value);
        if (!s->inval_status) {
            s->occupied &= ~BIT_ULL(value);
        }
        return;
    }
    /* Max-pending limit is fixed to the qualified 64-tag geometry. */
    if (offset == 0x1210 && size == 4) {
        return;
    }
    qemu_log_mask(LOG_UNIMP, "modern-ans: unsupported write @0x%"HWADDR_PRIx
                  " value=0x%"PRIx64"\n", offset, value);
}

static const MemoryRegionOps ans_bar_ops = {
    .read = ans_bar_read, .write = ans_bar_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8, .unaligned = false },
    .impl = { .min_access_size = 4, .max_access_size = 8 },
};

static void ans_reset(DeviceState *dev)
{
    AppleModernANS *s = APPLE_MODERN_ANS(dev);
    s->negotiated = false;
    s->occupied = s->tcb_base[0] = s->tcb_base[1] = 0;
    s->linear = s->num_tcbs = s->inval_status = 0;
    s->reads = s->writes = s->submissions = s->rejected = s->crypto_rejected = 0;
}

static void ans_counter(Object *obj, Visitor *v, const char *name,
                         void *opaque, Error **errp)
{
    uint64_t value = *(uint64_t *)((uint8_t *)APPLE_MODERN_ANS(obj) +
                                  (size_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}

static void ans_transport_counter(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp)
{
    AppleModernANS *s = APPLE_MODERN_ANS(obj);
    AppleA7IOP *asc = &s->rtkit->parent_obj;
    uint64_t value = 0;
    switch ((size_t)opaque) {
    case 0: value = asc->diagnostic_mmio_reads; break;
    case 1: value = asc->diagnostic_mmio_writes; break;
    case 2: value = asc->ap_mailbox->diagnostic_mmio_reads; break;
    case 3: value = asc->ap_mailbox->diagnostic_mmio_writes; break;
    case 4: value = asc->iop_mailbox->diagnostic_enqueues; break;
    case 5: value = asc->ap_mailbox->diagnostic_dequeues; break;
    }
    visit_type_uint64(v, name, &value, errp);
}

static const VMStateDescription ans_vmstate = {
    .name = TYPE_APPLE_MODERN_ANS, .unmigratable = 1,
};
static void ans_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->vmsd = &ans_vmstate;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, ans_reset);
#define COUNTER(name, field) object_class_property_add(oc, name, "uint64", \
    ans_counter, NULL, NULL, (void *)offsetof(AppleModernANS, field))
    COUNTER("mmio-read-count", reads);
    COUNTER("mmio-write-count", writes);
    COUNTER("submission-count", submissions);
    COUNTER("rejected-count", rejected);
    COUNTER("crypto-rejected-count", crypto_rejected);
#undef COUNTER
#define TRANSPORT(name, index) object_class_property_add(oc, name, "uint64", \
    ans_transport_counter, NULL, NULL, (void *)(index))
    TRANSPORT("wrapper-read-count", 0);
    TRANSPORT("wrapper-write-count", 1);
    TRANSPORT("mailbox-read-count", 2);
    TRANSPORT("mailbox-write-count", 3);
    TRANSPORT("guest-message-count", 4);
    TRANSPORT("guest-receive-count", 5);
#undef TRANSPORT
}

SysBusDevice *apple_modern_ans_create(Object *parent, MemoryRegion *ram,
                                     uint64_t ram_base, uint64_t wrapper_size,
                                     Error **errp)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_ANS);
    AppleModernANS *s = APPLE_MODERN_ANS(dev);
    PCIDevice *pci;
    s->ram_base = ram_base;
    s->ram_size = memory_region_size(ram);
    object_property_add_child(parent, "ans", OBJECT(dev));
    memory_region_init(&s->dma_root, OBJECT(dev), "ans.dma-root", UINT64_MAX);
    memory_region_init_alias(&s->dma_ram, OBJECT(dev), "ans.dma-ram", ram, 0,
                             s->ram_size);
    memory_region_add_subregion(&s->dma_root, ram_base, &s->dma_ram);
    address_space_init(&s->dma_as, &s->dma_root, "ans.ram-only-dma");
    memory_region_init(&s->pci_mem, OBJECT(dev), "ans.private-pci-mem", UINT64_MAX);
    memory_region_init(&s->pci_io, OBJECT(dev), "ans.private-pci-io", 65536);
    s->bus = pci_register_root_bus(dev, "ans-private-pci", ans_irq, ans_irq_map,
        s, &s->pci_mem, &s->pci_io, 0, 1, TYPE_PCIE_BUS);
    PCI_HOST_BRIDGE(dev)->bus = s->bus;
    pci_setup_iommu(s->bus, &ans_iommu_ops, s);
    pci = pci_new(-1, TYPE_NVME);
    s->nvme = NVME(pci);
    DEVICE(pci)->id = g_strdup("modern-ans-nvme");
    object_property_add_child(OBJECT(dev), "nvme", OBJECT(pci));
    object_property_set_str(OBJECT(pci), "serial", "MODERN-ANS-MODEL", &error_abort);
    object_property_set_bool(OBJECT(pci), "is-apple-ans", true, &error_abort);
    object_property_set_bool(OBJECT(pci), "apple-linear-sq", true, &error_abort);
    object_property_set_bool(OBJECT(pci), "ioeventfd", false, &error_abort);
    object_property_set_uint(OBJECT(pci), "max_ioqpairs", 1, &error_abort);
    object_property_set_uint(OBJECT(pci), "mqes", ANS_MAX_TAGS - 1, &error_abort);
    object_property_set_uint(OBJECT(pci), "mdts", 8, &error_abort);
    if (!qdev_realize(DEVICE(pci), BUS(s->bus), errp)) {
        return NULL;
    }
    s->rtkit = apple_rtkit_new(s, "ANS2", wrapper_size, APPLE_A7IOP_V6, &ans_rtkit_ops);
    object_property_add_child(OBJECT(dev), "rtkit", OBJECT(s->rtkit));
    if (!sysbus_realize(SYS_BUS_DEVICE(s->rtkit), errp)) {
        return NULL;
    }
    memory_region_init_io(&s->bar, OBJECT(dev), &ans_bar_ops, s, "ans.bar", ANS_BAR_SIZE);
    memory_region_init_alias(&s->nvme_alias, OBJECT(dev), "ans.nvme-registers",
                             &s->nvme->iomem, 0, 0x1200);
    memory_region_add_subregion_overlap(&s->bar, 0, &s->nvme_alias, 1);
    memory_region_init_alias(&s->secure, OBJECT(dev), "ans.secure-bar", &s->bar,
                             0, ANS_SECURE_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->bar);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->secure);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev),
                     sysbus_mmio_get_region(SYS_BUS_DEVICE(s->rtkit), 0));
    sysbus_pass_irq(SYS_BUS_DEVICE(dev), SYS_BUS_DEVICE(s->rtkit));
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq);
    if (!sysbus_realize(SYS_BUS_DEVICE(dev), errp)) {
        return NULL;
    }
    return SYS_BUS_DEVICE(dev);
}

static const TypeInfo ans_type = {
    .name = TYPE_APPLE_MODERN_ANS, .parent = TYPE_PCI_HOST_BRIDGE,
    .instance_size = sizeof(AppleModernANS), .class_init = ans_class_init,
};
static void ans_register(void) { type_register_static(&ans_type); }
type_init(ans_register);
