/* SPDX-License-Identifier: GPL-2.0-or-later
 * Owned-data fixture for the real QEMU T8110 IOMMU and AddressSpace wrappers.
 * Linked against the built emulator with only system/main.c replaced.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/bswap.h"
#include "qemu/main-loop.h"
#include "qemu/rcu.h"
#include "hw/arm/apple-silicon/dart-t8110.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "system/address-spaces.h"
#include "system/dma.h"
#include "system/replay.h"
#include "system/system.h"

#define OWN_RAM_BASE (UINT64_C(1) << 40)
#define OWN_RAM_SIZE (8 * APPLE_DART_T8110_PAGE_SIZE)
#define OWN_MMIO_BASE (UINT64_C(1) << 41)
#define TABLE0 OWN_RAM_BASE
#define TABLE1 (OWN_RAM_BASE + APPLE_DART_T8110_PAGE_SIZE)
#define TABLE2 (OWN_RAM_BASE + 2 * APPLE_DART_T8110_PAGE_SIZE)
#define DATA_A (OWN_RAM_BASE + 3 * APPLE_DART_T8110_PAGE_SIZE)
#define DATA_B (OWN_RAM_BASE + 4 * APPLE_DART_T8110_PAGE_SIZE)
#define IOVA ((UINT64_C(1) << 40) | (UINT64_C(5) << 25) | \
              (UINT64_C(7) << 14) | UINT64_C(0x20))
#define ERROR_FLAG UINT32_C(0x80000000)
#define OWN_TYPE "owned-dart-t8110-dma-fixture"

static unsigned checks, finalized;
static MemoryRegion owned_ram;
static uint8_t *ram;
static DeviceState *device;
static AddressSpace *dma_as;
static struct {
    int level;
    unsigned rises, falls;
} observed_irq;

int (*qemu_main)(void);

#define CHECK(condition, description) do { \
    checks++; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL check %u: %s (line %d)\n", \
                checks, description, __LINE__); \
        exit(1); \
    } \
} while (0)

static void owned_finalize(Object *obj)
{
    finalized++;
}

static const TypeInfo owned_type = {
    .name = OWN_TYPE,
    .parent = TYPE_APPLE_DART_T8110,
    .instance_finalize = owned_finalize,
};

static void irq_observer(void *opaque, int line, int level)
{
    if (level != observed_irq.level) {
        if (level) {
            observed_irq.rises++;
        } else {
            observed_irq.falls++;
        }
    }
    observed_irq.level = level;
}

static uint64_t counter(const char *name)
{
    return object_property_get_uint(OBJECT(device), name, &error_abort);
}

static void write_reg(uint32_t offset, uint32_t value)
{
    uint8_t bytes[4];
    stl_le_p(bytes, value);
    CHECK(address_space_write(&address_space_memory, OWN_MMIO_BASE + offset,
            MEMTXATTRS_UNSPECIFIED, bytes, sizeof(bytes)) == MEMTX_OK,
          "real MMIO write succeeds");
}

static uint32_t read_reg(uint32_t offset)
{
    uint8_t bytes[4] = { 0 };
    CHECK(address_space_read(&address_space_memory, OWN_MMIO_BASE + offset,
            MEMTXATTRS_UNSPECIFIED, bytes, sizeof(bytes)) == MEMTX_OK,
          "real MMIO read succeeds");
    return ldl_le_p(bytes);
}

static void physical_put(uint64_t address, uint64_t value)
{
    CHECK(address >= OWN_RAM_BASE && address + 8 <= OWN_RAM_BASE + OWN_RAM_SIZE,
          "owned physical write stays inside fixture RAM");
    stq_le_p(ram + address - OWN_RAM_BASE, value);
}

static uint64_t physical_get(uint64_t address)
{
    CHECK(address >= OWN_RAM_BASE && address + 8 <= OWN_RAM_BASE + OWN_RAM_SIZE,
          "owned physical read stays inside fixture RAM");
    return ldq_le_p(ram + address - OWN_RAM_BASE);
}

static uint64_t leaf_address(void)
{
    return TABLE2 + ((IOVA >> 14) & 0x7ff) * 8;
}

static uint64_t full_leaf(uint64_t physical, uint64_t permissions)
{
    return (physical >> 4) | 1 | (UINT64_C(0xfff) << 40) | permissions;
}

static void configure(uint64_t physical, uint64_t permissions)
{
    physical_put(TABLE0 + ((IOVA >> 36) & 0x7ff) * 8, (TABLE1 >> 4) | 1);
    physical_put(TABLE1 + ((IOVA >> 25) & 0x7ff) * 8, (TABLE2 >> 4) | 1);
    physical_put(leaf_address(), full_leaf(physical, permissions));
    write_reg(0x1400, (TABLE0 >> 12) | 1);
    write_reg(0x1000, 9); /* enable and three-level/four-level-mode selector */
    write_reg(0xc00, 1);
}

static void flush(void)
{
    write_reg(0x80, 0x100); /* stream 0 invalidation */
    CHECK(read_reg(0x80) == 0, "synchronous invalidation completes");
}

static MemTxResult dma_read(uint64_t address, void *bytes, size_t length)
{
    RCU_READ_LOCK_GUARD();
    return dma_memory_read(dma_as, address, bytes, length,
                            MEMTXATTRS_UNSPECIFIED);
}

static MemTxResult dma_write(uint64_t address, const void *bytes, size_t length)
{
    RCU_READ_LOCK_GUARD();
    return dma_memory_write(dma_as, address, bytes, length,
                             MEMTXATTRS_UNSPECIFIED);
}

static void dma_expect(uint64_t expected)
{
    uint8_t bytes[8] = { 0 };
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) == MEMTX_OK,
          "actual QEMU IOMMU address-space read succeeds");
    CHECK(ldq_le_p(bytes) == expected, "DMA reads the translated owned page");
}

static void fault(uint32_t code, bool write)
{
    uint32_t error = read_reg(0x100);
    CHECK((error & ERROR_FLAG) && (error & 0x7fff) == code,
          "fault status reports the expected failing translation");
    CHECK(!!(error & (UINT32_C(1) << 28)) == write,
          "fault status records read/write direction");
    CHECK(read_reg(0x170) == (uint32_t)IOVA &&
          read_reg(0x174) == (uint32_t)(IOVA >> 32),
          "fault address retains high IOVA bits");
    CHECK(read_reg(0x1c0) & 1, "fault stream bitmap includes stream zero");
    CHECK(observed_irq.level == 1, "real DART fault IRQ is asserted");
}

static void clear_fault(void)
{
    write_reg(0x100, UINT32_MAX);
    write_reg(0x1c0, UINT32_MAX);
    CHECK(read_reg(0x100) == 0 && read_reg(0x1c0) == 0,
          "status and stream W1C clear the fault");
    CHECK(observed_irq.level == 0, "fault W1C lowers the real IRQ");
}

static void query_permissions(IOMMUAccessFlags expected)
{
    IOMMUMemoryRegion *iommu = memory_region_get_iommu(dma_as->root);
    IOMMUMemoryRegionClass *klass;
    IOMMUTLBEntry entry;
    uint64_t faults = counter("faults");
    CHECK(iommu != NULL, "DMA AddressSpace root is a real QOM IOMMU region");
    klass = IOMMU_MEMORY_REGION_GET_CLASS(iommu);
    entry = klass->translate(iommu, IOVA, IOMMU_NONE, 0);
    CHECK(entry.perm == expected, "IOMMU_NONE reports actual leaf permissions");
    CHECK(entry.target_as == &address_space_memory &&
          entry.translated_addr == DATA_A &&
          entry.iova == (IOVA & ~(APPLE_DART_T8110_PAGE_SIZE - 1)),
          "permission query returns the actual high-address mapping");
    CHECK(counter("faults") == faults && observed_irq.level == 0,
          "permission queries do not raise transaction faults");
}

int main(int argc, char **argv)
{
    char options[][15] = { "-M", "none", "-nodefaults", "-display", "none",
                          "-monitor", "none", "-serial", "none", "-S" };
    char *arguments[G_N_ELEMENTS(options) + 1];
    const uint64_t pattern_a = UINT64_C(0x1122334455667788);
    const uint64_t pattern_b = UINT64_C(0x8899aabbccddeeff);
    const uint64_t replacement = UINT64_C(0x0badfeedcafef00d);
    uint8_t bytes[8];
    qemu_irq irq;
    uint64_t fault_count, translation_count;

    arguments[0] = argv[0];
    for (unsigned i = 0; i < G_N_ELEMENTS(options); i++) {
        arguments[i + 1] = options[i];
    }
    qemu_init(G_N_ELEMENTS(arguments), arguments);
    CHECK(bql_locked(), "qemu_init returns with the BQL held");
    type_register_static(&owned_type);
    memory_region_init_ram(&owned_ram, NULL, "owned-dart-dma-ram",
                            OWN_RAM_SIZE, &error_abort);
    memory_region_add_subregion(get_system_memory(), OWN_RAM_BASE, &owned_ram);
    ram = memory_region_get_ram_ptr(&owned_ram);
    memset(ram, 0, OWN_RAM_SIZE);
    physical_put(DATA_A + 0x20, pattern_a);
    physical_put(DATA_B + 0x20, pattern_b);

    device = qdev_new(OWN_TYPE);
    qdev_prop_set_uint32(device, "num-streams", 3);
    qdev_prop_set_uint32(device, "va-bits", 42);
    qdev_prop_set_uint32(device, "pa-bits", 42);
    qdev_prop_set_uint32(device, "revision", 2);
    CHECK(qdev_realize(device, NULL, &error_abort), "real DART device realizes");
    irq = qemu_allocate_irq(irq_observer, NULL, 0);
    sysbus_connect_irq(SYS_BUS_DEVICE(device), 0, irq);
    sysbus_mmio_map(SYS_BUS_DEVICE(device), 0, OWN_MMIO_BASE);
    dma_as = apple_dart_t8110_dma_as(APPLE_DART_T8110(device), 0);
    CHECK(dma_as != NULL &&
          apple_dart_t8110_dma_as(APPLE_DART_T8110(device), 3) == NULL,
          "realized stream AddressSpaces are bounded");
    CHECK(read_reg(0x1000) == 0 && read_reg(0xc00) == 0,
          "stream zero resets disabled");
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) != MEMTX_OK &&
          counter("faults") == 0 && observed_irq.level == 0,
          "disabled stream rejects real DMA without inventing a fault");

    write_reg(0xc00, 1);
    write_reg(0x1000, 9);
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) != MEMTX_OK,
          "invalid TTBR rejects real DMA");
    fault(1, false);
    write_reg(0x104, ERROR_FLAG);
    CHECK(observed_irq.level == 0, "fault mask lowers IRQ");
    write_reg(0x104, 0);
    CHECK(observed_irq.level == 1, "unmasking a retained fault raises IRQ");
    clear_fault();

    configure(DATA_A, 0);
    query_permissions(IOMMU_RW);
    dma_expect(pattern_a);
    stq_le_p(bytes, replacement);
    CHECK(dma_write(IOVA, bytes, sizeof(bytes)) == MEMTX_OK,
          "actual QEMU IOMMU AddressSpace write succeeds");
    CHECK(physical_get(DATA_A + 0x20) == replacement &&
          physical_get(DATA_B + 0x20) == pattern_b,
          "DMA write changes exactly the translated owned page");

    physical_put(leaf_address(), 0);
    flush();
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) != MEMTX_OK,
          "invalid leaf rejects actual DMA");
    fault(1 << 3, false);
    clear_fault();

    physical_put(leaf_address(), full_leaf(DATA_A, 1 << 2)); /* read only */
    flush();
    query_permissions(IOMMU_RO);
    dma_expect(replacement);
    stq_le_p(bytes, pattern_a);
    CHECK(dma_write(IOVA, bytes, sizeof(bytes)) != MEMTX_OK,
          "read-only page rejects actual DMA write");
    CHECK(physical_get(DATA_A + 0x20) == replacement,
          "rejected DMA write leaves owned physical data unchanged");
    fault(1 << 4, true);
    clear_fault();

    physical_put(leaf_address(), full_leaf(DATA_A, 1 << 3)); /* write only */
    flush();
    query_permissions(IOMMU_WO);
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) != MEMTX_OK,
          "write-only page rejects actual DMA read");
    fault(1 << 5, false);
    clear_fault();

    physical_put(leaf_address(), full_leaf(DATA_B, 0));
    flush();
    dma_expect(pattern_b);
    CHECK(read_reg(0x100) == 0, "edited mapping translates without a fault");
    write_reg(0xc20, 1);
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) != MEMTX_OK &&
          read_reg(0x100) == 0 && observed_irq.level == 0,
          "stream disable invalidates and rejects actual DMA");
    write_reg(0xc00, 1);
    dma_expect(pattern_b);
    write_reg(0x1000, 0);
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) != MEMTX_OK &&
          read_reg(0x100) == 0, "TCR zero rejects DMA instead of bypassing");
    write_reg(0x1000, 9);
    dma_expect(pattern_b);

    write_reg(0x1400, ((OWN_RAM_BASE + OWN_RAM_SIZE) >> 12) | 1);
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) != MEMTX_OK,
          "page-table DMA outside owned RAM rejects the transfer");
    fault(1 << 6, false);
    clear_fault();
    write_reg(0x1400, (TABLE0 >> 12) | 1);

    physical_put(leaf_address(), (DATA_B >> 4) | 1 |
                 (UINT64_C(8) << 52) | (UINT64_C(8) << 40));
    flush();
    CHECK(dma_read(IOVA, bytes, 4) == MEMTX_OK &&
          ldl_le_p(bytes) == (uint32_t)pattern_b,
          "four-byte subpage granule permits the declared owned word");
    CHECK(dma_read(IOVA + 4, bytes, 4) != MEMTX_OK,
          "next subpage word is rejected by the real IOMMU path");
    CHECK(read_reg(0x100) & (1 << 5), "subpage rejection reports read protection");
    clear_fault();
    physical_put(leaf_address(), full_leaf(DATA_B, 0));
    flush();
    dma_expect(pattern_b);
    fault_count = counter("faults");
    translation_count = counter("translations");

    device_cold_reset(device);
    CHECK(counter("faults") == 0 && counter("translations") == 0 &&
          counter("mmio-reads") == 0 && counter("mmio-writes") == 0,
          "device reset clears diagnostics before any MMIO read");
    CHECK(read_reg(0x1000) == 0 && read_reg(0x1400) == 0 &&
          read_reg(0xc00) == 0 && read_reg(0x100) == 0 && observed_irq.level == 0,
          "device reset clears stream, table and fault state");
    CHECK(dma_read(IOVA, bytes, sizeof(bytes)) != MEMTX_OK &&
          counter("faults") == 0, "reset stream rejects real DMA");
    configure(DATA_B, 0);
    dma_expect(pattern_b);

    qdev_unrealize(device);
    CHECK(apple_dart_t8110_dma_as(APPLE_DART_T8110(device), 0) == NULL,
          "unrealize removes the stream AddressSpace");
    CHECK(observed_irq.level == 0, "unrealize lowers IRQ");
    CHECK(address_space_read(&address_space_memory, OWN_MMIO_BASE,
            MEMTXATTRS_UNSPECIFIED, bytes, 4) != MEMTX_OK,
          "unrealize removes the actual MMIO mapping");
    drain_call_rcu();
    CHECK(qdev_realize(device, NULL, &error_abort),
          "same object realizes again after AddressSpace teardown");
    sysbus_mmio_map(SYS_BUS_DEVICE(device), 0, OWN_MMIO_BASE);
    dma_as = apple_dart_t8110_dma_as(APPLE_DART_T8110(device), 0);
    CHECK(dma_as != NULL && counter("faults") == 0,
          "re-realize supplies a clean stream AddressSpace");
    configure(DATA_A, 0);
    dma_expect(replacement);

    qdev_unrealize(device);
    object_unparent(OBJECT(device));
    for (unsigned i = 0; i < 4; i++) {
        drain_call_rcu();
    }
    object_unref(OBJECT(device));
    device = NULL;
    dma_as = NULL;
    for (unsigned i = 0; i < 4 && finalized == 0; i++) {
        drain_call_rcu();
    }
    CHECK(finalized == 1, "DART owner is finalized after real AS/RCU teardown");
    qemu_free_irq(irq);

    /* AS roots exist even when the device was never mapped into physical MMIO.
     * Such roots must also leave QEMU's FlatView cache during unrealize.
     */
    device = qdev_new(OWN_TYPE);
    CHECK(qdev_realize(device, NULL, &error_abort),
          "DART can realize without ever mapping its MMIO region");
    CHECK(apple_dart_t8110_dma_as(APPLE_DART_T8110(device), 0) != NULL,
          "unmapped device still owns a real stream AddressSpace");
    qdev_unrealize(device);
    CHECK(apple_dart_t8110_dma_as(APPLE_DART_T8110(device), 0) == NULL,
          "unmapped device unrealize removes its AddressSpaces");
    object_unparent(OBJECT(device));
    object_unref(OBJECT(device));
    device = NULL;
    for (unsigned i = 0; i < 4 && finalized == 1; i++) {
        drain_call_rcu();
    }
    CHECK(finalized == 2,
          "unmapped DART owner finalizes after actual AS/RCU teardown");

    memory_region_del_subregion(get_system_memory(), &owned_ram);
    drain_call_rcu();
    object_unparent(OBJECT(&owned_ram));

    printf("{\"passed\":true,\"checks\":%u,\"faults_before_reset\":%"
           PRIu64 ",\"translations_before_reset\":%" PRIu64
           ",\"irq_rises\":%u,\"irq_falls\":%u,\"finalized\":%u,"
           "\"firmware_executed\":false,\"guest_executed\":false}\n",
           checks, fault_count, translation_count, observed_irq.rises,
           observed_irq.falls, finalized);
    qemu_cleanup(0);
    bql_unlock();
    replay_mutex_unlock();
    return 0;
}
