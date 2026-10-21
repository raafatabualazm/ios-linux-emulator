/*
 * Device-side stand-in for the multi-touch coprocessor's end of the iOS 27
 * HID transport FIFO ("SCMFIFO" over DockChannel), apple-modern machine option
 * modern-mtp-peer (default off, needs modern-mtp-input).
 *
 * It frames and answers the transport the way the coprocessor's firmware does:
 * it decodes every AP-to-device message, acknowledges commands, and sends
 * ready/descriptor/report messages to the AP. It runs no MTP firmware.
 *
 * Frame layout (confirmed against the guest's own byte dumps, claude-input
 * re/tools/scm_msg.py): 8-byte header {hdr_len=8, type, length, transfer_id,
 * interface, b6, b7}, 8-byte sub-header {flags, 0, payload_len, retcode},
 * payload, zero pad to 4, then u32 = ~sum of the little-endian words that
 * precede it. length = round_up(8 + payload_len, 4) with a sub-header, 0
 * without. type 0x11 = command / response, 0x12 = device report.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_ARM_APPLE_SILICON_MODERN_MTP_PEER_H
#define HW_ARM_APPLE_SILICON_MODERN_MTP_PEER_H

#include "hw/arm/apple-silicon/modern-dockchannel.h"

#define APPLE_MODERN_SCM_TYPE_CONTROL 0x11
#define APPLE_MODERN_SCM_TYPE_REPORT  0x12
#define APPLE_MODERN_SCM_HDR_LEN      8
#define APPLE_MODERN_SCM_SUB_LEN      8
#define APPLE_MODERN_SCM_MAX_MSG      0x1000

typedef struct AppleModernMtpPeer AppleModernMtpPeer;

/* Encode one message into out (at least APPLE_MODERN_SCM_MAX_MSG bytes); returns its length. */
size_t apple_modern_scm_encode(uint8_t *out, uint8_t type, uint8_t transfer_id,
                               uint8_t iface, const uint8_t *payload,
                               size_t payload_len, bool with_subheader,
                               uint8_t flags, uint32_t retcode);
/* Checksum of the 4-byte-multiple body that precedes the checksum word. */
uint32_t apple_modern_scm_checksum(const uint8_t *body, size_t len);

/* Attach a peer to dc and start it; the machine owns the result for its lifetime. */
AppleModernMtpPeer *apple_modern_mtp_peer_new(AppleModernDockChannelState *dc);

#endif
