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
#include "hw/arm/apple-silicon/modern-mtp-codec.h"

typedef struct AppleModernMtpPeer AppleModernMtpPeer;

/* Attach a peer to dc and start it; the machine owns the result for its lifetime. */
/* descriptor: "digitizer" serves a generic Digitizer/Touch Screen descriptor, anything else the firmware's own. */
AppleModernMtpPeer *apple_modern_mtp_peer_new(AppleModernDockChannelState *dc,
                                              const char *descriptor);

#endif
