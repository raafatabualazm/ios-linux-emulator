/*
 * Device-side stand-in for the multi-touch coprocessor's end of the HID
 * transport FIFO. See modern-mtp-peer.h for the frame layout.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/arm/apple-silicon/modern-mtp-peer.h"

#define PEER_QUEUE 16
#define PEER_LOG_FRAMES 256
#define PEER_REPLY_DELAY_NS (1 * SCALE_MS)
#define PEER_READY_DELAY_NS (5 * SCALE_MS)
#define PEER_RETRY_NS (2 * SCALE_MS)

/*
 * First-cut HID report descriptor for interface 1 (multi-touch): one finger of a
 * standard Digitizer / Touch Screen collection (tip switch + 7-bit contact id,
 * 16-bit X and Y, 0..2047). The transport accepts any descriptor; whether
 * AppleMultitouchHIDService consumes this shape is what the first touch
 * reports will show.
 */
/*
 * The HID report descriptor the real MTP firmware serves for the multi-touch
 * interface (D47_MtpFirmware A5PH/P4S1/P4B1 at 0x8a194, 29 bytes): a Digitizer
 * / Touch Screen application collection holding one vendor-page input that is a
 * single buffered-bytes report of 0x1ffff bits (16 KiB), i.e. an opaque
 * multitouch frame parsed by AppleMultitouchHIDService, not field-by-field HID.
 */
static const uint8_t mt_hid_descriptor_firmware[] = {
    0x05, 0x0d, 0x09, 0x04, 0xa1, 0x01, 0x06, 0x00, 0xff, 0x09, 0x23, 0x95,
    0x01, 0xa1, 0x00, 0x05, 0x0d, 0x09, 0x04, 0x77, 0xff, 0xff, 0x01, 0x00,
    0x82, 0x22, 0x01, 0xc0, 0xc0,
};

static const uint8_t mt_hid_descriptor_digitizer[] = {
    0x05, 0x0d, 0x09, 0x04, 0xa1, 0x01, 0x09, 0x22, 0xa1, 0x02,
    0x09, 0x42, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x09, 0x51, 0x75, 0x07, 0x95, 0x01, 0x81, 0x02,
    0x05, 0x01, 0x09, 0x30, 0x15, 0x00, 0x26, 0xff, 0x07, 0x75, 0x10, 0x95,
    0x01, 0x81, 0x02,
    0x09, 0x31, 0x15, 0x00, 0x26, 0xff, 0x07, 0x75, 0x10, 0x95, 0x01, 0x81,
    0x02,
    0xc0, 0xc0,
};

typedef struct PeerMsg {
    uint8_t data[APPLE_MODERN_SCM_MAX_MSG];
    size_t len;
    int64_t due;
} PeerMsg;

struct AppleModernMtpPeer {
    AppleModernDockChannelState *dc;
    QEMUTimer *timer;
    uint8_t acc[2 * APPLE_MODERN_SCM_MAX_MSG];  /* AP -> device bytes not yet a frame */
    size_t acc_len;
    PeerMsg *queue[PEER_QUEUE];
    unsigned queued;
    bool ready_sent;
    const uint8_t *hid_desc;     /* descriptor served for interface 1 */
    size_t hid_desc_len;
    unsigned frames_logged;
    uint64_t ap_frames, dev_frames;
};

uint32_t apple_modern_scm_checksum(const uint8_t *body, size_t len)
{
    uint32_t sum = 0;

    for (size_t i = 0; i + 4 <= len; i += 4) {
        sum += ldl_le_p(body + i);
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
        length = MAX(length, (size_t)APPLE_MODERN_SCM_SUB_LEN);
    }
    body = APPLE_MODERN_SCM_HDR_LEN + length;
    g_assert(body + 4 <= APPLE_MODERN_SCM_MAX_MSG);
    memset(out, 0, body + 4);
    out[0] = APPLE_MODERN_SCM_HDR_LEN;
    out[1] = type;
    stw_le_p(out + 2, length);
    out[4] = transfer_id;
    out[5] = iface;
    if (with_subheader) {
        out[8] = flags;
        stw_le_p(out + 10, payload_len);
        stl_le_p(out + 12, retcode);
        if (payload_len) {
            memcpy(out + 16, payload, payload_len);
        }
    }
    stl_le_p(out + body, apple_modern_scm_checksum(out, body));
    return body + 4;
}

static void peer_arm_timer(AppleModernMtpPeer *p)
{
    int64_t next = INT64_MAX;

    for (unsigned i = 0; i < p->queued; i++) {
        next = MIN(next, p->queue[i]->due);
    }
    if (next != INT64_MAX) {
        timer_mod(p->timer, next);
    }
}

static void peer_queue(AppleModernMtpPeer *p, const uint8_t *msg, size_t len,
                       int64_t delay_ns)
{
    PeerMsg *m;

    if (p->queued == PEER_QUEUE) {
        warn_report("apple-modern: mtp-peer reply queue full; dropping a message");
        return;
    }
    m = g_new0(PeerMsg, 1);
    memcpy(m->data, msg, len);
    m->len = len;
    m->due = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + delay_ns;
    p->queue[p->queued++] = m;
    peer_arm_timer(p);
}

static void peer_log_frame(AppleModernMtpPeer *p, const char *dir,
                           const uint8_t *f, size_t len)
{
    char hex[3 * 40 + 8];
    size_t payload = len > 16 + 4 ? lduw_le_p(f + 10) : 0;
    size_t show = MIN(payload, (size_t)32);

    if (p->frames_logged >= PEER_LOG_FRAMES) {
        return;
    }
    p->frames_logged++;
    hex[0] = 0;
    for (size_t i = 0; i < show; i++) {
        snprintf(hex + 3 * i, 4, "%02x ", f[16 + i]);
    }
    warn_report("apple-modern: mtp-peer %s type 0x%02x tid %u iface %u flags 0x%02x "
                "payload %zu bytes%s: %s", dir, f[1], f[4], f[5],
                len >= 16 ? f[8] : 0, payload, payload > show ? " (head)" : "",
                hex);
}

/* Handle one complete, checksummed AP -> device frame. */
static void peer_handle(AppleModernMtpPeer *p, const uint8_t *f, size_t len)
{
    uint8_t out[APPLE_MODERN_SCM_MAX_MSG];
    size_t n;

    p->ap_frames++;
    peer_log_frame(p, "AP->dev", f, len);
    if (f[1] != APPLE_MODERN_SCM_TYPE_CONTROL) {
        return;
    }
    /*
     * Every command is acknowledged: same transfer id, interface and flags,
     * empty payload, retcode 0. Replies that carry data (descriptors, feature
     * reads) are added as the transport asks for them.
     */
    {
        bool get = len >= 16 && (f[8] & 1);   /* flags bit 0: 1 = GET, 0 = SET */
        size_t plen = len >= 20 ? lduw_le_p(f + 10) : 0;

        /*
         * A GET gets its own request payload back (report id and arguments
         * echoed) until the real per-report contents are known; a SET gets an
         * empty acknowledgement.
         */
        static const uint8_t power_on[4] = { 0x41, 1, 1, 0 };
        bool power = get && f[5] == 0 && plen >= 1 && f[16] == 0x41;

        n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_CONTROL, f[4], f[5],
                                    power ? power_on : (get ? f + 16 : NULL),
                                    power ? sizeof(power_on) : (get ? plen : 0),
                                    true, len >= 16 ? f[8] : 0, 0);
    }
    peer_queue(p, out, n, PEER_REPLY_DELAY_NS);
}

static void peer_tx(void *opaque, const uint8_t *data, size_t len)
{
    AppleModernMtpPeer *p = opaque;

    if (p->acc_len + len > sizeof(p->acc)) {
        warn_report("apple-modern: mtp-peer AP->device buffer overflow; resetting");
        p->acc_len = 0;
        return;
    }
    memcpy(p->acc + p->acc_len, data, len);
    p->acc_len += len;
    while (p->acc_len >= APPLE_MODERN_SCM_HDR_LEN + 4) {
        size_t total;

        if (p->acc[0] != APPLE_MODERN_SCM_HDR_LEN) {
            warn_report("apple-modern: mtp-peer AP->device stream lost framing "
                        "(first byte 0x%02x); resetting", p->acc[0]);
            p->acc_len = 0;
            return;
        }
        total = APPLE_MODERN_SCM_HDR_LEN + lduw_le_p(p->acc + 2) + 4;
        if (total > APPLE_MODERN_SCM_MAX_MSG) {
            warn_report("apple-modern: mtp-peer AP->device frame of %zu bytes is "
                        "too long; resetting", total);
            p->acc_len = 0;
            return;
        }
        if (p->acc_len < total) {
            return;
        }
        if (ldl_le_p(p->acc + total - 4) !=
            apple_modern_scm_checksum(p->acc, total - 4)) {
            warn_report("apple-modern: mtp-peer AP->device frame has a bad "
                        "checksum; dropped");
        } else {
            peer_handle(p, p->acc, total);
        }
        memmove(p->acc, p->acc + total, p->acc_len - total);
        p->acc_len -= total;
    }
}

static void peer_timer(void *opaque)
{
    AppleModernMtpPeer *p = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    for (unsigned i = 0; i < p->queued;) {
        PeerMsg *m = p->queue[i];

        if (m->due > now) {
            i++;
            continue;
        }
        if (!apple_modern_dockchannel_push_rx(p->dc, m->data, m->len)) {
            m->due = now + PEER_RETRY_NS;   /* FIFO full: the AP will drain it */
            i++;
            continue;
        }
        p->dev_frames++;
        peer_log_frame(p, "dev->AP", m->data, m->len);
        g_free(m);
        memmove(&p->queue[i], &p->queue[i + 1],
                (p->queued - i - 1) * sizeof(p->queue[0]));
        p->queued--;
    }
    peer_arm_timer(p);
}

/* The AP armed its first asynchronous receive: it is listening, so say READY. */
static void peer_arm(void *opaque, uint32_t thresh)
{
    AppleModernMtpPeer *p = opaque;
    uint8_t out[APPLE_MODERN_SCM_MAX_MSG];
    static const uint8_t ready[4] = { 0xf1, 1, 1, 0 };  /* interface 1, status 1 */
    size_t n;

    if (p->ready_sent) {
        return;
    }
    p->ready_sent = true;
    n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_REPORT, 0, 0, ready,
                                sizeof(ready), true, 0, 0);
    peer_queue(p, out, n, PEER_READY_DELAY_NS);

    /*
     * Descriptor packet for interface 1, a report 0xf0 on the comm interface:
     * {0xf0, u16 version=1, u8 interface, char name[16], u16 more=0} followed
     * by sections {u16 type, u16 length, body}; type 0 is the HID report
     * descriptor. more=0 completes the interface's descriptor set.
     */
    {
        uint8_t pkt[22 + 4 + 64];

        g_assert(p->hid_desc_len <= 64);
        size_t k = 0;

        memset(pkt, 0, sizeof(pkt));
        pkt[k++] = 0xf0;
        stw_le_p(pkt + k, 1);
        k += 2;
        pkt[k++] = 1;
        memcpy(pkt + k, "multi-touch", 11);
        k += 16;
        stw_le_p(pkt + k, 0);
        k += 2;
        stw_le_p(pkt + k, 0);
        stw_le_p(pkt + k + 2, p->hid_desc_len);
        k += 4;
        memcpy(pkt + k, p->hid_desc, p->hid_desc_len);
        k += p->hid_desc_len;
        n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_REPORT, 0, 0, pkt, k,
                                    true, 0, 0);
        peer_queue(p, out, n, PEER_READY_DELAY_NS + 10 * SCALE_MS);
    }
}

AppleModernMtpPeer *apple_modern_mtp_peer_new(AppleModernDockChannelState *dc,
                                              const char *descriptor)
{
    AppleModernMtpPeer *p = g_new0(AppleModernMtpPeer, 1);

    p->dc = dc;
    if (descriptor && !strcmp(descriptor, "digitizer")) {
        p->hid_desc = mt_hid_descriptor_digitizer;
        p->hid_desc_len = sizeof(mt_hid_descriptor_digitizer);
    } else {
        p->hid_desc = mt_hid_descriptor_firmware;
        p->hid_desc_len = sizeof(mt_hid_descriptor_firmware);
    }
    p->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, peer_timer, p);
    apple_modern_dockchannel_set_peer(dc, peer_tx, p);
    apple_modern_dockchannel_set_arm_cb(dc, peer_arm, p);
    return p;
}
