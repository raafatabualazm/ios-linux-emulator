/*
 * Frame codec of the device-side multi-touch stand-in: the SCMFIFO message
 * framing and the Apple multitouch report (0x44) that rides inside it. Pure
 * byte shuffling with no QEMU dependencies, so it can be tested on its own
 * against bytes the guest itself logged.
 *
 * SCMFIFO message: 8-byte header {hdr_len=8, type, u16 length, transfer_id,
 * interface, b6, b7}, 8-byte sub-header {flags, 0, u16 payload_len, u32
 * retcode}, payload, zero pad to 4, then u32 = ~sum of the little-endian words
 * that precede it. length = round_up(8 + payload_len, 4) with a sub-header, 0
 * without. type 0x11 = command / response, 0x12 = device report.
 *
 * Multitouch report 0x44 (decoded from MultitouchSupport; the same bytes the
 * t8030 model in mt-spi.c sends to iOS 14): 28-byte header, then one 20-byte
 * path per finger. Positions are 0.01 mm from the bottom-left of the sensor,
 * velocities 1/8 mm/s.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_ARM_APPLE_SILICON_MODERN_MTP_CODEC_H
#define HW_ARM_APPLE_SILICON_MODERN_MTP_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APPLE_MODERN_SCM_TYPE_CONTROL 0x11
#define APPLE_MODERN_SCM_TYPE_REPORT  0x12
#define APPLE_MODERN_SCM_HDR_LEN      8
#define APPLE_MODERN_SCM_SUB_LEN      8
#define APPLE_MODERN_SCM_MAX_MSG      0x1000

/* Encode one message into out (at least APPLE_MODERN_SCM_MAX_MSG bytes); returns its length. */
size_t apple_modern_scm_encode(uint8_t *out, uint8_t type, uint8_t transfer_id,
                               uint8_t iface, const uint8_t *payload,
                               size_t payload_len, bool with_subheader,
                               uint8_t flags, uint32_t retcode);
/* Checksum of the 4-byte-multiple body that precedes the checksum word. */
uint32_t apple_modern_scm_checksum(const uint8_t *body, size_t len);

/*
 * Interface announcement (management report 0xf0): {0xf0, u16 version 1, u8
 * interface, char name[16], u16 more = 0}, section 0 = the HID report
 * descriptor, section 4 = ready status 0. Returns the packet length; hid_len
 * must be at most 64.
 */
#define APPLE_MODERN_MT_INIT_MAX (22 + 4 + 64 + 6)
size_t apple_modern_mt_init_packet(uint8_t *out, uint8_t iface, const char *name,
                                   const uint8_t *hid_desc, size_t hid_len);

#define APPLE_MODERN_MT_REPORT_ID 0x44
#define APPLE_MODERN_MT_HDR_LEN   28
#define APPLE_MODERN_MT_PATH_LEN  20
#define APPLE_MODERN_MT_FRAME_LEN (APPLE_MODERN_MT_HDR_LEN + APPLE_MODERN_MT_PATH_LEN)

enum {
    APPLE_MODERN_MT_STAGE_NOT_TRACKING = 0,
    APPLE_MODERN_MT_STAGE_START_IN_RANGE = 1,
    APPLE_MODERN_MT_STAGE_HOVER_IN_RANGE = 2,
    APPLE_MODERN_MT_STAGE_MAKE_TOUCH = 3,
    APPLE_MODERN_MT_STAGE_TOUCHING = 4,
    APPLE_MODERN_MT_STAGE_BREAK_TOUCH = 5,
    APPLE_MODERN_MT_STAGE_LINGER_IN_RANGE = 6,
    APPLE_MODERN_MT_STAGE_OUT_OF_RANGE = 7,
};

/*
 * One report 0x44 with a single path (id 1, finger 1, hand 1). ms must be
 * non-zero and increase from frame to frame; vx and vy are clamped to s16.
 * Writes APPLE_MODERN_MT_FRAME_LEN bytes and returns that length.
 */
size_t apple_modern_mt_frame(uint8_t *out, uint8_t counter, uint32_t ms,
                             uint8_t stage, int x, int y, int64_t vx, int64_t vy);

/*
 * Velocity for a path that moved dpos (0.01 mm) in dt_ms milliseconds, in the
 * unit the report uses (1/8 mm/s): dpos * 80 / dt_ms. dt_ms of 0 gives 0.
 */
int64_t apple_modern_mt_velocity(int dpos, uint32_t dt_ms);

#endif
