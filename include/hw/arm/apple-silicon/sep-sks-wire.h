/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_ARM_APPLE_SILICON_SEP_SKS_WIRE_H
#define HW_ARM_APPLE_SILICON_SEP_SKS_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APPLE_SEP_SKS_HEADER_MAX 80u
#define APPLE_SEP_SKS_WIRE_MAX (4u + APPLE_SEP_SKS_HEADER_MAX)

typedef struct AppleSEPSKSWire {
    uint32_t version;
    uint32_t flags;
    size_t header_size;       /* Excludes the four-byte length prefix. */
    size_t body_offset;
    size_t body_size;
    size_t hash_offset;       /* Excludes the prefix and stored digest. */
    size_t hash_size;         /* Header bytes to hash before the body. */
} AppleSEPSKSWire;

/*
 * T8140 AppleSEPKeyStore: v1 header 72, v2 header 80, four-byte prefix.
 * Legacy preserves the simulator's historical 80-byte v1/v2 container.
 * This validates framing only; no service, digest or cryptography is implied.
 * On failure, view is untouched. Wire size is bounded by the mailbox's u16.
 */
bool apple_sep_sks_wire_parse(const uint8_t *buf, size_t size, bool modern,
                            AppleSEPSKSWire *view);

#endif
