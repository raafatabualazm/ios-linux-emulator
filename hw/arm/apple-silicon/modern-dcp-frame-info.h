/* iOS 27 native D594 frame information. SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef APPLE_MODERN_DCP_FRAME_INFO_H
#define APPLE_MODERN_DCP_FRAME_INFO_H

#include <stdint.h>
#include <string.h>

#define DCP_FRAME_INFO_PACKET_SIZE (12u + 0x730u)

static inline void dcp_frame_put32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) {
        p[i] = value >> (8 * i);
    }
}

static inline void dcp_frame_put64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; i++) {
        p[i] = value >> (8 * i);
    }
}

/* BootKC a36b9241, D594 a175764 and native frame-info fanout 91ddd90.
 * All time arguments are guest mach ticks, never host nanoseconds.
 * Issued is this model's acceptance event; VBL is its actual presentation
 * boundary. These are explicit model events, not inferred A408 fields.
 * Unknown fence/min/max times stay absent (zero), as supported by QuartzCore.
 * The AP applies each subscriber's mask; blob+dc=0 still delivers type3.
 */
static inline void dcp_frame_info_encode(uint8_t *packet, uint32_t id,
                                        uint64_t issued, uint64_t requested,
                                        uint64_t presented)
{
    uint8_t *input = packet + 12;
    uint8_t *blob = input + 0x27;

    memset(packet, 0, DCP_FRAME_INFO_PACKET_SIZE);
    memcpy(packet, "495D", 4);
    dcp_frame_put32(packet + 4, 0x730);
    dcp_frame_put32(input, id);
    input[4] = 1;
    dcp_frame_put64(blob, issued);
    dcp_frame_put64(blob + 8, requested);
    dcp_frame_put64(blob + 0x10, presented);
    dcp_frame_put64(blob + 0x18, presented);
    dcp_frame_put32(blob + 0x38, id);
    dcp_frame_put32(input + 0x727, 1);
    input[0x72c] = 1;
}

#endif
