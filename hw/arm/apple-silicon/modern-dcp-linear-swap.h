/* Bounded iOS 27 A408 software-frame decoder; SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef APPLE_MODERN_DCP_LINEAR_SWAP_H
#define APPLE_MODERN_DCP_LINEAR_SWAP_H

#include <stddef.h>
#include <stdint.h>

#define DCP_LINEAR_SWAP_INPUT_SIZE 0xff4u
#define DCP_LINEAR_SWAP_WIDTH 1024u
#define DCP_LINEAR_SWAP_HEIGHT 768u
#define DCP_LINEAR_SWAP_STRIDE (DCP_LINEAR_SWAP_WIDTH * 4u)
#define DCP_LINEAR_SWAP_BYTES (DCP_LINEAR_SWAP_STRIDE * DCP_LINEAR_SWAP_HEIGHT)

typedef struct DcpLinearSwap {
    uint32_t id;
    uint64_t iova;
} DcpLinearSwap;

static inline uint32_t dcp_swap_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline uint64_t dcp_swap_u64(const uint8_t *p)
{
    return dcp_swap_u32(p) | (uint64_t)dcp_swap_u32(p + 4) << 32;
}

/*
 * BootKC a36b9241, A408 stub a163208 and descriptor serializer a1990fc.
 * This deliberately accepts only the measured whole-screen, layer-0 software
 * frame. It does not implement scaling, blending, tiling, compression or YUV.
 * Return a refusal reason or NULL. Output is written only after all checks.
 */
static inline const char *dcp_linear_swap_decode(const uint8_t *p, size_t len,
                                                DcpLinearSwap *out)
{
    const uint8_t *d;
    uint32_t id, sid;
    uint64_t dva, iova;

    if (!p || !out || len != DCP_LINEAR_SWAP_INPUT_SIZE) {
        return "wrong A408 payload size";
    }
    if ((p[0xfea] & 1) || (p[0xfeb] & 1)) {
        return "null transaction or primary descriptor";
    }
    /* Low four bits name changed layers; changed null layers are clears.
     * Bit 31 updates the background, covered by this opaque full-frame layer.
     * IOMFB's a15f304/a15f474 and SwapSetBackgroundColor a3f800 prove these.
     */
    if (!(dcp_swap_u32(p + 0x14c) & 1) ||
        (dcp_swap_u32(p + 0x14c) & ~UINT32_C(0x8000000f))) {
        return "requires changed primary layer and known mask bits";
    }
    for (unsigned i = 1; i < 4; i++) {
        if (!(p[0xfeb + i] & 1) || dcp_swap_u64(p + 0xf90 + i * 8) ||
            dcp_swap_u32(p + 0x9c + i * 4)) {
            return "additional layer is populated";
        }
    }
    if (dcp_swap_u32(p + 0xac) || dcp_swap_u32(p + 0xb0) ||
        dcp_swap_u32(p + 0xb4) != DCP_LINEAR_SWAP_WIDTH ||
        dcp_swap_u32(p + 0xb8) != DCP_LINEAR_SWAP_HEIGHT ||
        dcp_swap_u32(p + 0x10c) || dcp_swap_u32(p + 0x110) ||
        dcp_swap_u32(p + 0x114) != DCP_LINEAR_SWAP_WIDTH ||
        dcp_swap_u32(p + 0x118) != DCP_LINEAR_SWAP_HEIGHT ||
        dcp_swap_u32(p + 0xec) != 1) {
        return "unsupported crop, destination or layer flags";
    }
    d = p + 0x6e0; /* Four packed 0x22c-byte descriptor records follow transaction. */
    if ((d[0] & 1) || dcp_swap_u64(d + 0x1ed) ||
        dcp_swap_u32(d + 3) || dcp_swap_u32(d + 7)) {
        return "tiled, compressed or planar surface";
    }
    if (dcp_swap_u32(d + 0xb) != UINT32_C(0x42475241) ||
        d[0x19] != 4 || d[0x1a] || d[0x1b] != 1 || d[0x1c] != 1) {
        return "requires packed BGRA8888";
    }
    if (dcp_swap_u32(d + 0x15) != DCP_LINEAR_SWAP_STRIDE ||
        dcp_swap_u32(d + 0x1d) ||
        dcp_swap_u32(d + 0x21) != DCP_LINEAR_SWAP_WIDTH ||
        dcp_swap_u32(d + 0x25) != DCP_LINEAR_SWAP_HEIGHT ||
        dcp_swap_u32(d + 0x29) < DCP_LINEAR_SWAP_BYTES) {
        return "unsupported geometry or allocation extent";
    }
    id = dcp_swap_u32(p + 0x98);
    sid = dcp_swap_u32(p + 0x9c);
    if (!id || !sid || sid != dcp_swap_u32(d + 0x35)) {
        return "invalid swap or surface identity";
    }
    dva = dcp_swap_u64(p + 0xf90);
    iova = dva & UINT64_C(0xfffffffff);
    if ((dva >> 36) != UINT64_C(0x10) ||
        iova > UINT64_C(0x1000000000) - DCP_LINEAR_SWAP_BYTES) {
        return "unsupported display DVA or extent";
    }
    *out = (DcpLinearSwap) { .id = id, .iova = iova };
    return NULL;
}

#endif
