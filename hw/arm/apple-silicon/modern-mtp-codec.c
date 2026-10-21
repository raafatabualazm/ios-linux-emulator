/*
 * Frame codec of the device-side multi-touch stand-in. See modern-mtp-codec.h.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifdef APPLE_MODERN_MTP_CODEC_STANDALONE
#include <assert.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/modern-mtp-codec.h"

static void put16(uint8_t *p, uint32_t v)
{
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, v & 0xffff);
    put16(p + 2, v >> 16);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

uint32_t apple_modern_scm_checksum(const uint8_t *body, size_t len)
{
    uint32_t sum = 0;

    for (size_t i = 0; i + 4 <= len; i += 4) {
        sum += get32(body + i);
    }
    return ~sum;
}

size_t apple_modern_scm_encode(uint8_t *out, uint8_t type, uint8_t transfer_id,
                               uint8_t iface, const uint8_t *payload,
                               size_t payload_len, bool with_subheader,
                               uint8_t flags, uint32_t retcode)
{
    size_t length = 0, body;

    if (with_subheader) {
        length = (APPLE_MODERN_SCM_SUB_LEN + payload_len + 3) & ~(size_t)3;
    }
    body = APPLE_MODERN_SCM_HDR_LEN + length;
    assert(body + 4 <= APPLE_MODERN_SCM_MAX_MSG);
    memset(out, 0, body + 4);
    out[0] = APPLE_MODERN_SCM_HDR_LEN;
    out[1] = type;
    put16(out + 2, length);
    out[4] = transfer_id;
    out[5] = iface;
    if (with_subheader) {
        out[8] = flags;
        put16(out + 10, payload_len);
        put32(out + 12, retcode);
        if (payload_len) {
            memcpy(out + 16, payload, payload_len);
        }
    }
    put32(out + body, apple_modern_scm_checksum(out, body));
    return body + 4;
}

size_t apple_modern_mt_init_packet(uint8_t *out, uint8_t iface, const char *name,
                                   const uint8_t *hid_desc, size_t hid_len)
{
    size_t k = 0, name_len = strlen(name);

    assert(hid_len <= 64 && name_len < 16);
    memset(out, 0, APPLE_MODERN_MT_INIT_MAX);
    out[k++] = 0xf0;                       /* management report: interface descriptor */
    put16(out + k, 1);                     /* descriptor packet version */
    k += 2;
    out[k++] = iface;
    memcpy(out + k, name, name_len);
    k += 16;
    put16(out + k, 0);                     /* more packets: none */
    k += 2;
    put16(out + k, 0);                     /* section 0: HID report descriptor */
    put16(out + k + 2, hid_len);
    k += 4;
    memcpy(out + k, hid_desc, hid_len);
    k += hid_len;
    put16(out + k, 4);                     /* section 4: ready status */
    put16(out + k + 2, 2);
    put16(out + k + 4, 0);                 /* 0 = HID, non-zero = inactive */
    k += 6;
    return k;
}

size_t apple_modern_mt_frame(uint8_t *out, uint8_t counter, uint32_t ms,
                             uint8_t stage, int x, int y, int64_t vx, int64_t vy)
{
    uint8_t *path = out + APPLE_MODERN_MT_HDR_LEN;

    if (vx > INT16_MAX) {
        vx = INT16_MAX;
    } else if (vx < INT16_MIN) {
        vx = INT16_MIN;
    }
    if (vy > INT16_MAX) {
        vy = INT16_MAX;
    } else if (vy < INT16_MIN) {
        vy = INT16_MIN;
    }
    memset(out, 0, APPLE_MODERN_MT_FRAME_LEN);
    out[0] = APPLE_MODERN_MT_REPORT_ID;
    out[1] = counter;                      /* frame counter, wraps */
    out[2] = APPLE_MODERN_MT_HDR_LEN;      /* header length */
    out[3] = 0;                            /* header version */
    put32(out + 4, ms);                    /* milliseconds, non-zero, increasing */
    out[16] = 1;                           /* path count */
    out[17] = APPLE_MODERN_MT_PATH_LEN;    /* path stride */
    path[0] = 1;                           /* path id */
    path[1] = stage;
    path[2] = 1;                           /* finger id */
    path[3] = 1;                           /* hand id */
    put16(path + 4, (uint16_t)x);
    put16(path + 6, (uint16_t)y);
    put16(path + 8, (uint16_t)(int16_t)vx);
    put16(path + 10, (uint16_t)(int16_t)vy);
    put16(path + 12, 660);                 /* major radius, 0.01 mm */
    put16(path + 14, 580);                 /* minor radius */
    put16(path + 16, 19317);               /* angle, units of pi/32768 */
    put16(path + 18, 100);                 /* zTotal, /256 */
    return APPLE_MODERN_MT_FRAME_LEN;
}

int64_t apple_modern_mt_velocity(int dpos, uint32_t dt_ms)
{
    return dt_ms ? (int64_t)dpos * 80 / (int64_t)dt_ms : 0;
}
