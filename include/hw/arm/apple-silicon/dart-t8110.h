/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_ARM_APPLE_DART_T8110_H
#define HW_ARM_APPLE_DART_T8110_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APPLE_DART_T8110_STREAMS 256U
#define APPLE_DART_T8110_PAGE_SIZE UINT64_C(0x4000)
#define APPLE_DART_T8110_READ 1U
#define APPLE_DART_T8110_WRITE 2U

typedef struct AppleDARTT8110Geometry {
    uint32_t num_streams, va_bits, pa_bits, revision, mmio_size;
} AppleDARTT8110Geometry;

typedef struct AppleDARTT8110Core {
    AppleDARTT8110Geometry geometry;
    uint32_t enabled[8], tcr[APPLE_DART_T8110_STREAMS];
    uint32_t ttbr[APPLE_DART_T8110_STREAMS];
    uint32_t error, error_mask, error_streams[8];
    uint64_t error_address;
    uint32_t protect, protect_lock;
    uint64_t reads, writes, unknown_reads, unknown_writes;
    uint64_t translations, faults, flushes;
} AppleDARTT8110Core;

typedef struct AppleDARTT8110Flush {
    bool valid, all;
    uint32_t sid;
} AppleDARTT8110Flush;

typedef struct AppleDARTT8110Translation {
    uint64_t address, mask;
    unsigned permissions;
} AppleDARTT8110Translation;

/* Callback reads exactly one little-endian guest physical PTE; no host pointer. */
typedef bool (*AppleDARTT8110ReadPTE)(void *opaque, uint64_t address,
                                    uint64_t *pte);

bool apple_dart_t8110_core_init(AppleDARTT8110Core *s,
                               const AppleDARTT8110Geometry *geometry,
                               const char **reason);
void apple_dart_t8110_core_reset(AppleDARTT8110Core *s);
bool apple_dart_t8110_core_read(AppleDARTT8110Core *s, uint64_t offset,
                               unsigned size, uint32_t *value);
bool apple_dart_t8110_core_write(AppleDARTT8110Core *s, uint64_t offset,
                                unsigned size, uint32_t value,
                                AppleDARTT8110Flush *flush);
bool apple_dart_t8110_core_irq(const AppleDARTT8110Core *s);
/* access=0 queries mapping/permissions without raising a transaction fault. */
bool apple_dart_t8110_core_translate(AppleDARTT8110Core *s, uint32_t sid,
                                    uint64_t iova, unsigned access,
                                    AppleDARTT8110ReadPTE read_pte,
                                    void *opaque,
                                    AppleDARTT8110Translation *translation);

#ifndef APPLE_DART_T8110_STANDALONE
#include "hw/sysbus.h"
#include "system/memory.h"

#define TYPE_APPLE_DART_T8110 "apple-dart-t8110"
OBJECT_DECLARE_SIMPLE_TYPE(AppleDARTT8110State, APPLE_DART_T8110)

/* The device must be realized first. Each stream has an independent IOVA AS. */
AddressSpace *apple_dart_t8110_dma_as(AppleDARTT8110State *s, uint32_t sid);
#endif
#endif
