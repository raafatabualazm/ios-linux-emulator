/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef APPLE_SEP_SKS_STANDALONE
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/sep-sks-wire.h"

static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

bool apple_sep_sks_wire_parse(const uint8_t *buf, size_t size, bool modern,
                            AppleSEPSKSWire *view)
{
    AppleSEPSKSWire next;

    if (!buf || !view || size < 24 || size > UINT16_MAX) {
        return false;
    }
    next.version = load32(buf + 20);
    if (next.version != 1 && next.version != 2) {
        return false;
    }
    next.header_size = modern && next.version == 1 ? 72 : 80;
    next.body_offset = 4 + next.header_size;
    if (load32(buf) != next.header_size || size < next.body_offset) {
        return false;
    }
    next.body_size = size - next.body_offset;
    next.flags = load32(buf + 32);
    next.hash_offset = 20;
    next.hash_size = next.version == 1 ? 56 : 64;
    *view = next;
    return true;
}
