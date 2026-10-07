/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/dart-t8110.h"

/* Owned RAM and PTEs: no Apple firmware, SEP protocol or cryptography. */
#define RAM_BASE UINT64_C(0x10000000000)
#define RAM_SIZE 0x20000U
#define IOVA UINT64_C(0x100000043fc)
#define L0 RAM_BASE
#define L1 (RAM_BASE + 0x4000)
#define L2 (RAM_BASE + 0x8000)
#define DATA0 (RAM_BASE + 0xc000)
#define DATA1 (RAM_BASE + 0x10000)

static unsigned checks;
static unsigned char ram[RAM_SIZE];
static unsigned pte_reads;
static uint64_t fail_pte;

#define CHECK(test) do { \
    checks++; \
    if (!(test)) { \
        fprintf(stderr, "FAIL %s:%u: %s\n", __FILE__, __LINE__, #test); \
        exit(1); \
    } \
} while (0)

static void put64(uint64_t pa, uint64_t value)
{
    CHECK(pa >= RAM_BASE && pa - RAM_BASE <= RAM_SIZE - 8);
    for (unsigned i = 0; i < 8; i++) {
        ram[pa - RAM_BASE + i] = value >> (i * 8);
    }
}

static uint64_t pte_address(uint64_t pa)
{
    return pa >> 4;
}

static uint32_t ttbr_address(uint64_t pa)
{
    return (uint32_t)(pa >> 12) | 1;
}

static bool read_pte(void *opaque, uint64_t pa, uint64_t *pte)
{
    (void)opaque;
    pte_reads++;
    if (pa == fail_pte || pa < RAM_BASE || pa - RAM_BASE > RAM_SIZE - 8) {
        return false;
    }
    *pte = 0;
    for (unsigned i = 0; i < 8; i++) {
        *pte |= (uint64_t)ram[pa - RAM_BASE + i] << (i * 8);
    }
    return true;
}

static AppleDARTT8110Flush wr(AppleDARTT8110Core *s, uint64_t reg,
                              uint32_t value)
{
    AppleDARTT8110Flush flush;
    CHECK(apple_dart_t8110_core_write(s, reg, 4, value, &flush));
    return flush;
}

static uint32_t rd(AppleDARTT8110Core *s, uint64_t reg)
{
    uint32_t value = 0;
    CHECK(apple_dart_t8110_core_read(s, reg, 4, &value));
    return value;
}

/* Test adapter exercises real production walks and transfers owned RAM only.
 * It does not substitute for QEMU AddressSpace/IOMMU-wrapper qualification.
 */
static bool dma(AppleDARTT8110Core *s, unsigned sid, uint64_t iova,
                 unsigned char *data, size_t size, bool write)
{
    while (size) {
        AppleDARTT8110Translation translation;
        if (!apple_dart_t8110_core_translate(s, sid, iova, write ? 2 : 1,
                                              read_pte, NULL, &translation)) {
            return false;
        }
        size_t amount = translation.mask + 1 - (iova & translation.mask);
        if (amount > size) {
            amount = size;
        }
        uint64_t pa = translation.address;
        if (pa < RAM_BASE || pa - RAM_BASE > RAM_SIZE ||
            amount > RAM_SIZE - (pa - RAM_BASE)) {
            return false;
        }
        if (write) {
            memcpy(ram + pa - RAM_BASE, data, amount);
        } else {
            memcpy(data, ram + pa - RAM_BASE, amount);
        }
        size -= amount;
        data += amount;
        iova += amount;
    }
    return true;
}

static void clear_fault(AppleDARTT8110Core *s)
{
    wr(s, 0x100, UINT32_MAX);
    wr(s, 0x1c0, UINT32_MAX);
    CHECK(!apple_dart_t8110_core_irq(s));
}

static uint64_t leaf_pa(uint64_t iova)
{
    return L2 + ((iova >> 14) & 0x7ff) * 8;
}

static void seed_tables(void)
{
    memset(ram, 0, sizeof(ram));
    put64(L0 + ((IOVA >> 36) & 0x7ff) * 8, pte_address(L1) | 1);
    put64(L1 + ((IOVA >> 25) & 0x7ff) * 8, pte_address(L2) | 1);
    put64(leaf_pa(IOVA), pte_address(DATA0) | UINT64_C(0xfff0000000001));
    put64(leaf_pa(IOVA + 0x4000), pte_address(DATA1) |
          UINT64_C(0xfff0000000001));
    pte_reads = 0;
    fail_pte = 0;
}

static void configure(AppleDARTT8110Core *s)
{
    wr(s, 0xc00, 7);
    wr(s, 0x1400, ttbr_address(L0));
    wr(s, 0x1000, 9); /* enable + four-level */
}

static void fault_is(AppleDARTT8110Core *s, unsigned sid, unsigned bit,
                       uint64_t iova, bool write)
{
    uint32_t status = rd(s, 0x100);
    CHECK(status & (UINT32_C(1) << 31));
    CHECK((status & 0x7fff) == (UINT32_C(1) << bit));
    CHECK(((status >> 20) & 0xff) == sid);
    CHECK(!!(status & (UINT32_C(1) << 28)) == write);
    CHECK(rd(s, 0x170) == (uint32_t)iova);
    CHECK(rd(s, 0x174) == (uint32_t)(iova >> 32));
    CHECK(apple_dart_t8110_core_irq(s));
    CHECK(rd(s, 0x1c0) & (1U << sid));
}

static void gate(AppleDARTT8110Core *s)
{
    unsigned char data[32], reference[32], before[32];
    AppleDARTT8110Translation translation;
    AppleDARTT8110Flush flush;

    seed_tables();
    CHECK(rd(s, 0x0) == 14U << 24);
    CHECK(rd(s, 0xc) == 0x30003);
    CHECK(((rd(s, 0x8) >> 16) & 0x3f) == 42);
    CHECK(((rd(s, 0x8) >> 24) & 0x3f) == 42);
    CHECK(!apple_dart_t8110_core_irq(s));
    CHECK(!dma(s, 0, IOVA, data, sizeof(data), false));
    CHECK(s->faults == 0 && pte_reads == 0);
    configure(s);

    for (unsigned i = 0; i < sizeof(reference); i++) {
        reference[i] = (unsigned char)(i * 17 + 31);
    }
    CHECK(dma(s, 0, IOVA, reference, sizeof(reference), true));
    CHECK(!memcmp(ram + DATA0 - RAM_BASE + 0x3fc, reference, sizeof(reference)));
    memset(data, 0, sizeof(data));
    CHECK(dma(s, 0, IOVA, data, sizeof(data), false));
    CHECK(!memcmp(data, reference, sizeof(data)));
    CHECK(!apple_dart_t8110_core_irq(s));
    CHECK(pte_reads == 6);

    /* A page-crossing transfer uses two independently translated leaf pages. */
    uint64_t crossing = (IOVA & ~UINT64_C(0x3fff)) + 0x3ff0;
    CHECK(dma(s, 0, crossing, reference, sizeof(reference), true));
    CHECK(!memcmp(ram + DATA0 - RAM_BASE + 0x3ff0, reference, 16));
    CHECK(!memcmp(ram + DATA1 - RAM_BASE, reference + 16, 16));
    CHECK(dma(s, 0, crossing, data, sizeof(data), false));
    CHECK(!memcmp(data, reference, sizeof(data)));

    /* Stream1 has no TTBR; physical aliasing must never make the DMA succeed. */
    wr(s, 0x1004, 9);
    memset(data, 0xa5, sizeof(data));
    memcpy(before, data, sizeof(data));
    CHECK(!dma(s, 1, IOVA, data, sizeof(data), false));
    CHECK(!memcmp(data, before, sizeof(data)));
    fault_is(s, 1, 0, IOVA, false);
    wr(s, 0x104, 1);
    CHECK(!apple_dart_t8110_core_irq(s));
    wr(s, 0x104, 0);
    CHECK(apple_dart_t8110_core_irq(s));
    clear_fault(s);

    /* Invalid table levels report different normal DART fault codes. */
    put64(L0 + ((IOVA >> 36) & 0x7ff) * 8, 0);
    CHECK(!dma(s, 0, IOVA, data, 4, false));
    fault_is(s, 0, 1, IOVA, false);
    clear_fault(s);
    put64(L0 + ((IOVA >> 36) & 0x7ff) * 8, pte_address(L1) | 1);
    put64(L1 + ((IOVA >> 25) & 0x7ff) * 8, 0);
    CHECK(!dma(s, 0, IOVA, data, 4, false));
    fault_is(s, 0, 2, IOVA, false);
    clear_fault(s);
    put64(L1 + ((IOVA >> 25) & 0x7ff) * 8, pte_address(L2) | 1);
    put64(leaf_pa(IOVA), 0);
    CHECK(!dma(s, 0, IOVA, data, 4, false));
    fault_is(s, 0, 3, IOVA, false);
    clear_fault(s);

    /* Denied writes leave the destination intact. Read denial leaves caller
     * bytes intact. Permission failures do not become successful replies. */
    put64(leaf_pa(IOVA), pte_address(DATA0) | UINT64_C(0xfff0000000005));
    memcpy(before, ram + DATA0 - RAM_BASE + 0x3fc, sizeof(before));
    CHECK(!dma(s, 0, IOVA, reference, sizeof(reference), true));
    CHECK(!memcmp(before, ram + DATA0 - RAM_BASE + 0x3fc, sizeof(before)));
    fault_is(s, 0, 4, IOVA, true);
    clear_fault(s);
    put64(leaf_pa(IOVA), pte_address(DATA0) | UINT64_C(0xfff0000000009));
    CHECK(apple_dart_t8110_core_translate(s, 0, IOVA, 0, read_pte, NULL,
                                           &translation));
    CHECK(translation.permissions == APPLE_DART_T8110_WRITE);
    CHECK(translation.address == DATA0 + (IOVA & 0x3fff));
    CHECK(!apple_dart_t8110_core_irq(s));
    memset(data, 0xb6, sizeof(data));
    memcpy(before, data, sizeof(before));
    CHECK(!dma(s, 0, IOVA, data, sizeof(data), false));
    CHECK(!memcmp(before, data, sizeof(data)));
    fault_is(s, 0, 5, IOVA, false);
    clear_fault(s);

    fail_pte = leaf_pa(IOVA);
    uint64_t faults_before_query = s->faults;
    CHECK(!apple_dart_t8110_core_translate(s, 0, IOVA, 0, read_pte, NULL,
                                            &translation));
    CHECK(s->faults == faults_before_query && !apple_dart_t8110_core_irq(s));
    CHECK(!dma(s, 0, IOVA, data, 4, false));
    fault_is(s, 0, 6, IOVA, false);
    clear_fault(s);
    fail_pte = 0;

    /* A replacement leaf plus SID flush requests a real IOMMU invalidation;
     * the uncached production core sees the new physical page afterward. */
    put64(leaf_pa(IOVA), pte_address(DATA1) | UINT64_C(0xfff0000000001));
    flush = wr(s, 0x80, 0x100);
    CHECK(flush.valid && !flush.all && flush.sid == 0);
    CHECK(rd(s, 0x80) == 0);
    CHECK(dma(s, 0, IOVA, reference, sizeof(reference), true));
    CHECK(!memcmp(ram + DATA1 - RAM_BASE + 0x3fc, reference, sizeof(reference)));
    flush = wr(s, 0x80, 0);
    CHECK(flush.valid && flush.all);

    /* Small subpage range returns a 4-byte granule; adjacent access faults. */
    unsigned word = (IOVA & 0x3fff) >> 2;
    put64(leaf_pa(IOVA), pte_address(DATA0) | 1 |
          (uint64_t)word << 52 | (uint64_t)word << 40);
    CHECK(apple_dart_t8110_core_translate(s, 0, IOVA, 1, read_pte, NULL,
                                           &translation));
    CHECK(translation.mask == 3 && translation.permissions == 3);
    CHECK(!dma(s, 0, IOVA + 4, data, 4, false));
    fault_is(s, 0, 5, IOVA + 4, false);
    clear_fault(s);

    /* Explicit full bypass translates physical addresses. TCR zero does not. */
    wr(s, 0x1000, 2);
    CHECK(dma(s, 0, DATA0 + 0x3fc, data, sizeof(data), false));
    CHECK(!memcmp(data, ram + DATA0 - RAM_BASE + 0x3fc, sizeof(data)));
    wr(s, 0x1000, 0);
    CHECK(!dma(s, 0, DATA0 + 0x3fc, data, sizeof(data), false));
    CHECK(!apple_dart_t8110_core_irq(s));

    /* A regular two-read walk uses a lower IOVA and one root TTBR. */
    uint64_t low_iova = 0x43fc;
    put64(leaf_pa(low_iova), pte_address(DATA0) | UINT64_C(0xfff0000000001));
    wr(s, 0x1400, ttbr_address(L1));
    wr(s, 0x1000, 1);
    pte_reads = 0;
    CHECK(dma(s, 0, low_iova, data, sizeof(data), false));
    CHECK(pte_reads == 2);
    CHECK(!dma(s, 0, IOVA, data, sizeof(data), false));
    fault_is(s, 0, 6, IOVA, false);
    clear_fault(s);

    /* Stream remapping uses target TTBR but keeps original stream fault SID. */
    wr(s, 0x1404, ttbr_address(L1));
    wr(s, 0x1000, 1 | 0x80 | 0x100);
    CHECK(dma(s, 0, low_iova, data, sizeof(data), false));
    wr(s, 0x1000, 1 | 0x80 | 0xf00);
    CHECK(!dma(s, 0, low_iova, data, sizeof(data), false));
    fault_is(s, 0, 0, low_iova, false);
    clear_fault(s);

    /* Register protection can be cleared, then locked until reset. */
    wr(s, 0x200, 1);
    wr(s, 0x1000, 123);
    CHECK(rd(s, 0x1000) == (1 | 0x80 | 0xf00));
    wr(s, 0x204, 1);
    wr(s, 0x1000, 9);
    CHECK(rd(s, 0x1000) == 9);
    wr(s, 0x200, 1);
    wr(s, 0x208, 1);
    wr(s, 0x204, 1);
    CHECK(rd(s, 0x200) == 1);
    wr(s, 0x1400, 0);
    CHECK(rd(s, 0x1400) == ttbr_address(L1));

    flush = wr(s, 0xc20, 7);
    CHECK(flush.valid && flush.all && rd(s, 0xc00) == 0);
    CHECK(!dma(s, 0, IOVA, data, 4, false));
    CHECK(!apple_dart_t8110_core_irq(s));
}

int main(void)
{
    AppleDARTT8110Core core;
    const AppleDARTT8110Geometry geometry = { 3, 42, 42, 2, 0x20000 };
    const char *reason;
    CHECK(apple_dart_t8110_core_init(&core, &geometry, &reason));
    CHECK(reason == NULL);
    for (unsigned pass = 0; pass < 2; pass++) {
        gate(&core);
        apple_dart_t8110_core_reset(&core);
        CHECK(core.geometry.num_streams == 3 && core.geometry.va_bits == 42);
        CHECK(core.reads == 0 && core.writes == 0 && core.faults == 0);
        CHECK(core.protect == 0 && core.protect_lock == 0);
        CHECK(!apple_dart_t8110_core_irq(&core));
        for (unsigned sid = 0; sid < APPLE_DART_T8110_STREAMS; sid++) {
            CHECK(core.tcr[sid] == 0 && core.ttbr[sid] == 0);
        }
        for (unsigned bank = 0; bank < 8; bank++) {
            CHECK(core.enabled[bank] == 0 && core.error_streams[bank] == 0);
        }
    }
    /* Geometry/MMIO bounds stay checked in production NDEBUG builds too. */
    AppleDARTT8110Geometry invalid = geometry;
    invalid.num_streams = 257;
    CHECK(!apple_dart_t8110_core_init(&core, &invalid, &reason));
    invalid = geometry;
    invalid.pa_bits = 43;
    CHECK(!apple_dart_t8110_core_init(&core, &invalid, &reason));
    invalid = geometry;
    invalid.revision = 1;
    CHECK(!apple_dart_t8110_core_init(&core, &invalid, &reason));
    invalid = geometry;
    invalid.mmio_size = 0x1000;
    CHECK(!apple_dart_t8110_core_init(&core, &invalid, &reason));
    CHECK(apple_dart_t8110_core_init(&core, &geometry, &reason));
    uint32_t value = 0;
    AppleDARTT8110Flush flush;
    CHECK(!apple_dart_t8110_core_read(&core, 0x20000, 4, &value));
    CHECK(!apple_dart_t8110_core_read(&core, 1, 4, &value));
    CHECK(!apple_dart_t8110_core_read(&core, 0, 8, &value));
    CHECK(!apple_dart_t8110_core_write(&core, 0x20000, 4, 0, &flush));
    CHECK(!apple_dart_t8110_core_write(&core, 0x80, 4, 0x200, &flush));
    CHECK(!apple_dart_t8110_core_write(&core, 0x80, 4, 0x1ff, &flush));
    CHECK(!apple_dart_t8110_core_read(&core, 0x100c, 4, &value));
    CHECK(!apple_dart_t8110_core_write(&core, 0x100c, 4, UINT32_MAX, &flush));
    AppleDARTT8110Translation translation;
    CHECK(!apple_dart_t8110_core_translate(&core, UINT32_MAX, IOVA, 1,
                                            read_pte, NULL, &translation));
    printf("PASS %u production-core checks; 2 DMA/fault/reset passes; "
           "QEMU AddressSpace wrapper not exercised\n", checks);
    return 0;
}
