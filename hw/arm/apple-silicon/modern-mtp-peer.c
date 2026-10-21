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
#include "ui/input.h"
#include "hw/arm/apple-silicon/modern-mtp-peer.h"

#define PEER_QUEUE 16
#define PEER_LOG_FRAMES 256
#define PEER_REPLY_DELAY_NS (1 * SCALE_MS)
#define PEER_READY_DELAY_NS (5 * SCALE_MS)
#define PEER_RETRY_NS (2 * SCALE_MS)

/*
 * Multitouch frames (report 0x44, decoded from MultitouchSupport and checked
 * against the t8030 model in mt-spi.c): 28-byte header, one 20-byte path per
 * finger. Positions are in 0.01 mm with the origin at the bottom-left of the
 * sensor, velocities in 1/8 mm/s.
 *
 * The guest's panel is the 1024x768 framebuffer, so the sensor surface served
 * for report 0xd9 is 100.00 x 75.00 mm. Whole multiples of 100 units matter:
 * the HID plug-in normalises with floor(size / 100), so a remainder could push
 * the far edge above 1.0.
 */
#define MT_SURFACE_W 10000
#define MT_SURFACE_H 7500
#define MT_FRAME_NS (16 * SCALE_MS)
#define MT_REPORT_ID 0x44
#define MT_HDR_LEN 28
#define MT_PATH_LEN 20
#define MT_STAGE_MAKE 3
#define MT_STAGE_TOUCHING 4
#define MT_STAGE_BREAK 5
#define MT_STAGE_LINGER 6
#define MT_STAGE_OUT 7

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

/*
 * Feature-report answers for interface 1 (multi-touch). These are the cached
 * GET responses the kernel itself carries for the AppleGenericMultitouch
 * controllers (BootKC personality "GetReportCachedResponse", first variant,
 * ExpectedVersion 896): the exact bytes a real controller returns for these
 * report ids. d47's own personality (D47S1) travels in the touch firmware
 * image, which is not retained, so the nearest shipped variant is served.
 */
typedef struct CachedGet {
    uint8_t id;
    uint8_t len;
    uint8_t data[96];
} CachedGet;

static const CachedGet mt_cached_gets_template[] = {
    { 0x7f, 5,  { 0x7f, 0x00, 0x00, 0x00, 0x00 } },
    { 0xa1, 7,  { 0xa1, 0x00, 0x00, 0x07, 0x00, 0x00, 0x02 } },
    { 0xd0, 23, { 0xd0, 0x03, 0x01, 0x00, 0x1e, 0x01, 0x00, 0x0e, 0x00, 0x08,
                  0x00, 0x1e, 0x01, 0x0e, 0x01, 0x00, 0x0b, 0x1e, 0x01, 0x01,
                  0x00, 0x0f, 0x00 } },
    { 0xd1, 2,  { 0xd1, 0xc0 } },
    { 0xd3, 13, { 0xd3, 0x01, 0x1f, 0x0f, 0x03, 0x80, 0x00, 0x0e, 0x1e, 0x00,
                  0x05, 0x00, 0x00 } },
    { 0xd9, 17, { 0xd9, 0x58, 0x18, 0x00, 0x00, 0xb7, 0x34, 0x00, 0x00, 0x26,
                  0xff, 0x24, 0xff, 0x76, 0x17, 0xd3, 0x33 } },
    { 0xdb, 81, { 0xdb, 0x01, 0x02, 0x00, 0xd1, 0xc0, 0x0d, 0x00, 0xd3, 0x01,
                  0x1f, 0x0f, 0x03, 0x80, 0x00, 0x0e, 0x1e, 0x00, 0x05, 0x00,
                  0x00, 0x17, 0x00, 0xd0, 0x03, 0x01, 0x00, 0x1e, 0x01, 0x00,
                  0x0e, 0x00, 0x08, 0x00, 0x1e, 0x01, 0x0e, 0x01, 0x00, 0x0b,
                  0x1e, 0x01, 0x01, 0x00, 0x0f, 0x00, 0x07, 0x00, 0xa1, 0x00,
                  0x00, 0x07, 0x00, 0x00, 0x02, 0x11, 0x00, 0xd9, 0x58, 0x18,
                  0x00, 0x00, 0xb7, 0x34, 0x00, 0x00, 0x26, 0xff, 0x24, 0xff,
                  0x76, 0x17, 0xd3, 0x33, 0x05, 0x00, 0x7f, 0x00, 0x00, 0x00,
                  0x00 } },
};

#define N_CACHED_GETS ARRAY_SIZE(mt_cached_gets_template)

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
    bool init_sent;
    CachedGet gets[N_CACHED_GETS];   /* feature-report answers for interface 1 */
    /*
     * Pointer-to-touch bridge: a primary-button drag is one finger. The pointer
     * position is kept in console units and turned into sensor units per frame.
     */
    QemuInputHandlerState *input;
    int abs_x, abs_y;            /* last pointer position, 0..INPUT_EVENT_ABS_MAX */
    bool touching;               /* primary button state after the latest sync */
    bool contact;                /* a contact is in progress (MakeTouch sent) */
    QEMUTimer *touch_timer;      /* one Touching frame per MT_FRAME_NS while down */
    uint8_t mt_frame;            /* frame counter, wraps */
    uint32_t mt_last_ms;         /* last timestamp used; strictly increasing */
    int mt_x, mt_y;              /* last position reported, sensor units */
    uint32_t mt_pos_ms;          /* timestamp that position was reported at */
    uint64_t touch_frames;
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
        const uint8_t *body = get ? f + 16 : NULL;
        size_t blen = get ? plen : 0;

        if (power) {
            body = power_on;
            blen = sizeof(power_on);
        } else if (get && f[5] == 1 && plen >= 1) {
            for (size_t i = 0; i < N_CACHED_GETS; i++) {
                if (p->gets[i].id == f[16]) {
                    body = p->gets[i].data;
                    blen = p->gets[i].len;
                    break;
                }
            }
        }
        n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_CONTROL, f[4], f[5],
                                    body, blen, true, len >= 16 ? f[8] : 0, 0);
    }
    peer_queue(p, out, n, PEER_REPLY_DELAY_NS);

    /*
     * The AP enables an interface with SET FEATURE 0xb4 [iface] once it has the
     * interface's descriptor. After the acknowledgement the device reports the
     * interface READY (report 0xf1, status 0 = HID): only then does the
     * transport register the interface. READY ahead of the descriptor is ignored.
     */
    if (!(len >= 16 && (f[8] & 1)) && f[5] == 0 && len >= 20 &&
        lduw_le_p(f + 10) >= 2 && f[16] == 0xb4) {
        const uint8_t ready[4] = { 0xf1, f[17], 0, 0 };

        n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_REPORT, 0, 0, ready,
                                    sizeof(ready), true, 0, 0);
        peer_queue(p, out, n, PEER_REPLY_DELAY_NS + PEER_READY_DELAY_NS);
    }
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

/*
 * The AP armed its first asynchronous receive: it is listening. The device
 * announces interface 1 with a descriptor packet (report 0xf0 on the comm
 * interface): {0xf0, u16 version=1, u8 interface, char name[16], u16 more=0},
 * then sections {u16 type, u16 length, body}. Type 0 is the HID report
 * descriptor, type 4 the ready status (0 = HID). more=0 completes the
 * interface. The AP answers with SET FEATURE 0xb4 [iface]; the READY report
 * follows that acknowledgement (see peer_handle).
 */
static void peer_arm(void *opaque, uint32_t thresh)
{
    AppleModernMtpPeer *p = opaque;
    uint8_t out[APPLE_MODERN_SCM_MAX_MSG];
    uint8_t pkt[22 + 4 + 64 + 6];
    size_t n, k = 0;

    if (p->init_sent) {
        return;
    }
    p->init_sent = true;
    g_assert(p->hid_desc_len <= 64);
    memset(pkt, 0, sizeof(pkt));
    pkt[k++] = 0xf0;
    stw_le_p(pkt + k, 1);
    k += 2;
    pkt[k++] = 1;
    memcpy(pkt + k, "multi-touch", 11);
    k += 16;
    stw_le_p(pkt + k, 0);                         /* more packets: none */
    k += 2;
    stw_le_p(pkt + k, 0);                         /* section 0: HID descriptor */
    stw_le_p(pkt + k + 2, p->hid_desc_len);
    k += 4;
    memcpy(pkt + k, p->hid_desc, p->hid_desc_len);
    k += p->hid_desc_len;
    stw_le_p(pkt + k, 4);                         /* section 4: ready status */
    stw_le_p(pkt + k + 2, 2);
    stw_le_p(pkt + k + 4, 0);
    k += 6;
    n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_REPORT, 0, 0, pkt, k,
                                true, 0, 0);
    peer_queue(p, out, n, PEER_READY_DELAY_NS);
}

/*
 * One multitouch frame for the single tracked finger (path 1). delay_ns is
 * when the frame is due on the virtual clock; its timestamp is that instant in
 * milliseconds, forced to be non-zero and strictly increasing (the library
 * rejects 0 and backward time). Velocity is the displacement since the previous
 * frame in 1/8 mm/s: dx[0.01 mm] * 80 / dt[ms].
 */
static void peer_send_mt(AppleModernMtpPeer *p, uint8_t stage, int x, int y,
                         int64_t delay_ns)
{
    uint8_t rep[MT_HDR_LEN + MT_PATH_LEN] = { 0 };
    uint8_t out[APPLE_MODERN_SCM_MAX_MSG];
    uint8_t *path = rep + MT_HDR_LEN;
    int64_t due = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + delay_ns;
    uint32_t ms = due / SCALE_MS + 1;
    int64_t vx = 0, vy = 0;
    size_t n;

    if (ms <= p->mt_last_ms) {
        ms = p->mt_last_ms + 1;
    }
    if (stage != MT_STAGE_MAKE && ms > p->mt_pos_ms) {
        vx = (int64_t)(x - p->mt_x) * 80 / (int64_t)(ms - p->mt_pos_ms);
        vy = (int64_t)(y - p->mt_y) * 80 / (int64_t)(ms - p->mt_pos_ms);
    }
    p->mt_last_ms = ms;
    p->mt_pos_ms = ms;
    p->mt_x = x;
    p->mt_y = y;

    rep[0] = MT_REPORT_ID;
    rep[1] = p->mt_frame++;
    rep[2] = MT_HDR_LEN;
    rep[3] = 0;                         /* header version */
    stl_le_p(rep + 4, ms);
    rep[16] = 1;                        /* path count */
    rep[17] = MT_PATH_LEN;              /* path stride */
    path[0] = 1;                        /* path id */
    path[1] = stage;
    path[2] = 1;                        /* finger id */
    path[3] = 1;                        /* hand id */
    stw_le_p(path + 4, x);
    stw_le_p(path + 6, y);
    stw_le_p(path + 8, (uint16_t)CLAMP(vx, INT16_MIN, INT16_MAX));
    stw_le_p(path + 10, (uint16_t)CLAMP(vy, INT16_MIN, INT16_MAX));
    stw_le_p(path + 12, 660);           /* major radius, 0.01 mm */
    stw_le_p(path + 14, 580);           /* minor radius */
    stw_le_p(path + 16, 19317);         /* angle, units of pi/32768 */
    stw_le_p(path + 18, 100);           /* zTotal, /256 */

    n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_REPORT, 0, 1, rep,
                                sizeof(rep), true, 0, 0);
    p->touch_frames++;
    peer_queue(p, out, n, delay_ns);
}

/* Pointer position in sensor units: x to the right, y up from the bottom edge. */
static void peer_pointer_sensor(AppleModernMtpPeer *p, int *x, int *y)
{
    *x = (uint64_t)p->abs_x * (MT_SURFACE_W - 1) / INPUT_EVENT_ABS_MAX;
    *y = (MT_SURFACE_H - 1) -
         (int)((uint64_t)p->abs_y * (MT_SURFACE_H - 1) / INPUT_EVENT_ABS_MAX);
}

static void peer_touch_tick(void *opaque)
{
    AppleModernMtpPeer *p = opaque;
    int x, y;

    if (!p->contact || !p->touching) {
        return;
    }
    peer_pointer_sensor(p, &x, &y);
    peer_send_mt(p, MT_STAGE_TOUCHING, x, y, 0);
    timer_mod(p->touch_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + MT_FRAME_NS);
}

static AppleModernMtpPeer *peer_of(DeviceState *dev)
{
    return APPLE_MODERN_DOCKCHANNEL(dev)->peer_opaque;
}

/*
 * Pointer events (VNC, QMP input-send-event, a tablet) become one finger: ABS
 * X/Y move it and the primary button is touch down / up.
 */
static void peer_input_event(DeviceState *dev, QemuConsole *src, InputEvent *evt)
{
    AppleModernMtpPeer *p = peer_of(dev);
    InputMoveEvent *move;
    InputBtnEvent *btn;

    switch (evt->type) {
    case INPUT_EVENT_KIND_ABS:
        move = evt->u.abs.data;
        if (move->axis == INPUT_AXIS_X) {
            p->abs_x = move->value;
        } else if (move->axis == INPUT_AXIS_Y) {
            p->abs_y = move->value;
        }
        break;
    case INPUT_EVENT_KIND_BTN:
        btn = evt->u.btn.data;
        if (btn->button == INPUT_BUTTON_LEFT) {
            p->touching = btn->down;
        }
        break;
    default:
        break;
    }
}

/*
 * Contact lifecycle, as the real controller reports it: MakeTouch, Touching
 * every frame, BreakTouch, LingerInRange, OutOfRange, one frame period apart.
 * Nothing is sent until the AP has been given the interface (init_sent).
 */
static void peer_input_sync(DeviceState *dev)
{
    AppleModernMtpPeer *p = peer_of(dev);
    int x, y;

    if (!p->init_sent) {
        return;
    }
    peer_pointer_sensor(p, &x, &y);
    if (p->touching && !p->contact) {
        p->contact = true;
        peer_send_mt(p, MT_STAGE_MAKE, x, y, 0);
        timer_mod(p->touch_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + MT_FRAME_NS);
    } else if (!p->touching && p->contact) {
        p->contact = false;
        timer_del(p->touch_timer);
        peer_send_mt(p, MT_STAGE_BREAK, x, y, 0);
        peer_send_mt(p, MT_STAGE_LINGER, x, y, MT_FRAME_NS);
        peer_send_mt(p, MT_STAGE_OUT, x, y, 2 * MT_FRAME_NS);
    }
}

static const QemuInputHandler peer_input_handler = {
    .name = "apple-modern MTP touch",
    .mask = INPUT_EVENT_MASK_BTN | INPUT_EVENT_MASK_ABS,
    .event = peer_input_event,
    .sync = peer_input_sync,
};

/*
 * The cached feature-report answers describe a real phone sensor. Replace the
 * sensor-surface report (0xd9: u32 width, u32 height, then the s16 x/y origin
 * and u16 x/y extent) with this machine's 100 x 75 mm surface, both in its own
 * answer and inside the 0xdb composite.
 */
static void peer_set_surface(AppleModernMtpPeer *p, unsigned w, unsigned h)
{
    static const uint8_t shipped[17] = {
        0xd9, 0x58, 0x18, 0x00, 0x00, 0xb7, 0x34, 0x00, 0x00, 0x26, 0xff, 0x24,
        0xff, 0x76, 0x17, 0xd3, 0x33,
    };
    uint8_t surface[17] = { 0xd9 };

    stl_le_p(surface + 1, w);
    stl_le_p(surface + 5, h);
    stw_le_p(surface + 9, 0);
    stw_le_p(surface + 11, 0);
    stw_le_p(surface + 13, w);
    stw_le_p(surface + 15, h);
    for (size_t i = 0; i < N_CACHED_GETS; i++) {
        for (size_t k = 0; k + sizeof(shipped) <= p->gets[i].len; k++) {
            if (!memcmp(p->gets[i].data + k, shipped, sizeof(shipped))) {
                memcpy(p->gets[i].data + k, surface, sizeof(surface));
            }
        }
    }
}

AppleModernMtpPeer *apple_modern_mtp_peer_new(AppleModernDockChannelState *dc,
                                              const char *descriptor)
{
    AppleModernMtpPeer *p = g_new0(AppleModernMtpPeer, 1);

    if (descriptor && strcmp(descriptor, "firmware")) {
        warn_report("apple-modern: mtp-peer-descriptor '%s' is not supported; "
                    "the multitouch service only understands the firmware's own "
                    "opaque-frame descriptor, which is served", descriptor);
    }
    p->dc = dc;
    p->hid_desc = mt_hid_descriptor_firmware;
    p->hid_desc_len = sizeof(mt_hid_descriptor_firmware);
    memcpy(p->gets, mt_cached_gets_template, sizeof(p->gets));
    peer_set_surface(p, MT_SURFACE_W, MT_SURFACE_H);
    p->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, peer_timer, p);
    p->touch_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, peer_touch_tick, p);
    apple_modern_dockchannel_set_peer(dc, peer_tx, p);
    apple_modern_dockchannel_set_arm_cb(dc, peer_arm, p);
    p->input = qemu_input_handler_register(DEVICE(dc), &peer_input_handler);
    qemu_input_handler_activate(p->input);
    return p;
}
