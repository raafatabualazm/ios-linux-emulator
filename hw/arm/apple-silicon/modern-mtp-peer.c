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
#include "qapi/error.h"
#include "qom/object.h"
#include "ui/input.h"
#include "hw/arm/apple-silicon/modern-mtp-peer.h"

#define PEER_QUEUE 16
#define PEER_LOG_FRAMES 4096
#define PEER_REPLY_DELAY_NS (1 * SCALE_MS)
#define PEER_READY_DELAY_NS (5 * SCALE_MS)
#define PEER_RETRY_NS (2 * SCALE_MS)
#define PEER_INITDONE_DELAY_NS (1500 * SCALE_MS)

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
#define MT_MIN_SPACING_NS (8 * SCALE_MS)   /* a real controller reports at 60 to 120 Hz */
#define MT_HIST 16               /* contact samples kept for the lift-off velocity */
#define MT_LIFT_WINDOW_MS 100    /* lift-off velocity is averaged over this window */

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
    { 0xbf, 9,  { 0xbf } },
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
    int64_t mt_last_due;         /* virtual ns the latest frame is due at */
    struct { uint32_t ms; int x, y; } mt_hist[MT_HIST];   /* recent contact samples */
    unsigned mt_hist_n;
    uint64_t touch_frames;
    bool initdone_sent;          /* the one-time "InitDone" status report */
    /* Scripted gesture (x-touch): tap or swipe, paced on the virtual clock. */
    QEMUTimer *gesture_timer;
    bool gesture_on;
    int64_t gesture_t0;          /* virtual ns of the first frame */
    int64_t gesture_dur;         /* ns from the first frame to the end point */
    int64_t gesture_hold;        /* ns the finger stays at the end point before lifting */
    int gesture_x0, gesture_y0, gesture_x1, gesture_y1;   /* ABS units */
    unsigned gesture_tick;
    const uint8_t *hid_desc;     /* descriptor served for interface 1 */
    size_t hid_desc_len;
    unsigned frames_logged;
    uint64_t ap_frames, dev_frames;
};

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
     * A real touch IC reports "Power on Reset and InitDone" (report 0x60,
     * code 0x11) once it is up. The kernel service is open by the time it has
     * read the sensor description (report 0xdb), so say it shortly after that
     * answer; user space turns it into a bootloaded notification.
     */
    if (!p->initdone_sent && len >= 20 && f[5] == 1 && (f[8] & 1) &&
        f[16] == 0xdb) {
        static const uint8_t initdone[2] = { 0x60, 0x11 };

        p->initdone_sent = true;
        n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_REPORT, 0, 1,
                                    initdone, sizeof(initdone), true, 0, 0);
        peer_queue(p, out, n, PEER_INITDONE_DELAY_NS);
    }

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
    uint8_t pkt[APPLE_MODERN_MT_INIT_MAX];
    size_t n, k;

    if (p->init_sent) {
        return;
    }
    p->init_sent = true;
    k = apple_modern_mt_init_packet(pkt, 1, "multi-touch", p->hid_desc,
                                    p->hid_desc_len);
    n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_REPORT, 0, 0, pkt, k,
                                true, 0, 0);
    peer_queue(p, out, n, PEER_READY_DELAY_NS);
}

/*
 * One multitouch frame for the single tracked finger (path 1). delay_ns is
 * when the frame is due on the virtual clock; its timestamp is that instant in
 * milliseconds, forced to be non-zero and strictly increasing (the library
 * rejects 0 and backward time). Velocity is the displacement since the previous
 * frame in the report's unit, 1/8 mm/s.
 */
static void peer_send_mt_v(AppleModernMtpPeer *p, uint8_t stage, int x, int y,
                           int64_t delay_ns, const int64_t *velocity)
{
    uint8_t rep[APPLE_MODERN_MT_FRAME_LEN];
    uint8_t out[APPLE_MODERN_SCM_MAX_MSG];
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int64_t due = now + delay_ns;
    uint32_t ms;
    int64_t vx = 0, vy = 0;
    size_t n;

    /*
     * Frames are never closer than MT_MIN_SPACING_NS: a pointer release can land
     * a millisecond after the last periodic frame, and the touch stack's
     * debounce treats frames that close together as unstable.
     */
    if (due < p->mt_last_due + MT_MIN_SPACING_NS) {
        due = p->mt_last_due + MT_MIN_SPACING_NS;
    }
    delay_ns = due - now;
    p->mt_last_due = due;
    ms = due / SCALE_MS + 1;
    if (ms <= p->mt_last_ms) {
        ms = p->mt_last_ms + 1;
    }
    if (stage != APPLE_MODERN_MT_STAGE_MAKE_TOUCH && ms > p->mt_pos_ms) {
        vx = apple_modern_mt_velocity(x - p->mt_x, ms - p->mt_pos_ms);
        vy = apple_modern_mt_velocity(y - p->mt_y, ms - p->mt_pos_ms);
    }
    if (velocity) {
        vx = velocity[0];
        vy = velocity[1];
    }
    p->mt_last_ms = ms;
    p->mt_pos_ms = ms;
    p->mt_x = x;
    p->mt_y = y;
    if (stage == APPLE_MODERN_MT_STAGE_MAKE_TOUCH) {
        p->mt_hist_n = 0;
    }
    if (stage <= APPLE_MODERN_MT_STAGE_TOUCHING) {
        unsigned slot = p->mt_hist_n++ % MT_HIST;

        p->mt_hist[slot].ms = ms;
        p->mt_hist[slot].x = x;
        p->mt_hist[slot].y = y;
    }

    apple_modern_mt_frame(rep, p->mt_frame++, ms, stage, x, y, vx, vy);
    n = apple_modern_scm_encode(out, APPLE_MODERN_SCM_TYPE_REPORT, 0, 1, rep,
                                sizeof(rep), true, 0, 0);
    p->touch_frames++;
    peer_queue(p, out, n, delay_ns);
}

static void peer_send_mt(AppleModernMtpPeer *p, uint8_t stage, int x, int y,
                         int64_t delay_ns)
{
    peer_send_mt_v(p, stage, x, y, delay_ns, NULL);
}

/*
 * Lift-off for a finger driven by a pointer: the pointer position changes in
 * steps at whatever rate the host delivers events, so the last frame can be
 * stationary even though the drag was fast. A flick is judged by the velocity at
 * release, so report the average velocity over the last MT_LIFT_WINDOW_MS of
 * the contact, as touch controllers do.
 */
static void peer_lift_off(AppleModernMtpPeer *p, int x, int y)
{
    int64_t now_ms = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / SCALE_MS + 1;
    int64_t v[2] = { 0, 0 };
    unsigned n = MIN(p->mt_hist_n, (unsigned)MT_HIST);

    for (unsigned i = 0; i < n; i++) {
        /* oldest sample inside the window, scanning from the newest */
        unsigned slot = (p->mt_hist_n - 1 - i) % MT_HIST;
        int64_t age = now_ms - p->mt_hist[slot].ms;

        if (age > MT_LIFT_WINDOW_MS) {
            break;
        }
        if (age > 0) {
            v[0] = apple_modern_mt_velocity(x - p->mt_hist[slot].x, age);
            v[1] = apple_modern_mt_velocity(y - p->mt_hist[slot].y, age);
        }
    }
    peer_send_mt_v(p, APPLE_MODERN_MT_STAGE_BREAK_TOUCH, x, y, 0, v);
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
    peer_send_mt(p, APPLE_MODERN_MT_STAGE_TOUCHING, x, y, 0);
    timer_mod(p->touch_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + MT_FRAME_NS);
}

/* Console pixels (the guest's 1024x768 framebuffer) to pointer ABS units. */
#define PEER_FB_W 1024
#define PEER_FB_H 768

static int peer_px_to_abs(int px, int size)
{
    return CLAMP(px, 0, size - 1) * INPUT_EVENT_ABS_MAX / (size - 1);
}

/*
 * One scripted gesture, one frame per MT_FRAME_NS on the virtual clock:
 * MakeTouch at the start point, Touching along the line, and the lift-off at
 * the end point followed by LingerInRange and OutOfRange. A tap is a gesture
 * with equal endpoints.
 *
 * The lift-off (BreakTouch) frame is the last step of the motion, so it still
 * carries the finger's velocity, as a real controller's does: a flick is judged
 * by the velocity at release. With a hold time the finger stays at the end
 * point for that long first and lifts with zero velocity (a drag and release).
 */
static void peer_gesture_tick(void *opaque)
{
    AppleModernMtpPeer *p = opaque;
    int64_t steps = MAX(1, (p->gesture_dur + MT_FRAME_NS - 1) / MT_FRAME_NS);
    int64_t last = steps + (p->gesture_hold + MT_FRAME_NS - 1) / MT_FRAME_NS;
    int64_t k = p->gesture_tick, m = MIN(k, steps);
    int x, y;

    if (!p->gesture_on) {
        return;
    }
    p->abs_x = p->gesture_x0 + (int)((int64_t)(p->gesture_x1 - p->gesture_x0) * m / steps);
    p->abs_y = p->gesture_y0 + (int)((int64_t)(p->gesture_y1 - p->gesture_y0) * m / steps);
    peer_pointer_sensor(p, &x, &y);
    if (k >= last) {
        peer_send_mt(p, APPLE_MODERN_MT_STAGE_BREAK_TOUCH, x, y, 0);
        peer_send_mt(p, APPLE_MODERN_MT_STAGE_LINGER_IN_RANGE, x, y, MT_FRAME_NS);
        peer_send_mt(p, APPLE_MODERN_MT_STAGE_OUT_OF_RANGE, x, y, 2 * MT_FRAME_NS);
        p->gesture_on = false;
        p->contact = false;
        return;
    }
    peer_send_mt(p, k == 0 ? APPLE_MODERN_MT_STAGE_MAKE_TOUCH : APPLE_MODERN_MT_STAGE_TOUCHING, x, y, 0);
    p->gesture_tick++;
    timer_mod(p->gesture_timer, p->gesture_t0 + (int64_t)p->gesture_tick * MT_FRAME_NS);
}

/*
 * QOM property "x-touch" on the DockChannel device (QMP qom-set):
 *   "tap X Y [HOLD_MS]"                          pixel coordinates of the 1024x768 panel
 *   "swipe X0 Y0 X1 Y1 [DURATION_MS [HOLD_MS]]"  e.g. "swipe 512 745 512 300 250"
 */
static void peer_x_touch_set(Object *obj, const char *value, Error **errp)
{
    AppleModernMtpPeer *p = APPLE_MODERN_DOCKCHANNEL(obj)->peer_opaque;
    int a, b, c, d, ms = 0, hold = 0;
    int n;

    if (!p || !p->init_sent) {
        error_setg(errp, "x-touch: the guest has not attached the touch device yet");
        return;
    }
    if (p->gesture_on || p->contact) {
        error_setg(errp, "x-touch: a contact is already in progress");
        return;
    }
    if ((n = sscanf(value, "tap %d %d %d", &a, &b, &ms)) >= 2) {
        c = a;
        d = b;
        ms = n == 3 ? ms : 60;
    } else if ((n = sscanf(value, "swipe %d %d %d %d %d %d", &a, &b, &c, &d, &ms, &hold)) >= 4) {
        ms = n >= 5 ? ms : 250;
        hold = n == 6 ? hold : 0;
    } else {
        error_setg(errp, "x-touch: expected 'tap X Y [MS]' or 'swipe X0 Y0 X1 Y1 [MS [HOLD_MS]]'");
        return;
    }
    p->gesture_x0 = peer_px_to_abs(a, PEER_FB_W);
    p->gesture_y0 = peer_px_to_abs(b, PEER_FB_H);
    p->gesture_x1 = peer_px_to_abs(c, PEER_FB_W);
    p->gesture_y1 = peer_px_to_abs(d, PEER_FB_H);
    p->gesture_dur = (int64_t)MAX(ms, 1) * SCALE_MS;
    p->gesture_hold = (int64_t)MAX(hold, 0) * SCALE_MS;
    p->gesture_tick = 0;
    p->gesture_on = true;
    p->contact = true;
    p->gesture_t0 = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    timer_mod(p->gesture_timer, p->gesture_t0);
    warn_report("apple-modern: mtp-peer gesture: %s", value);
}

static char *peer_x_touch_get(Object *obj, Error **errp)
{
    return g_strdup("");
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

    if (!p->init_sent || p->gesture_on) {
        return;
    }
    peer_pointer_sensor(p, &x, &y);
    if (p->touching && !p->contact) {
        p->contact = true;
        peer_send_mt(p, APPLE_MODERN_MT_STAGE_MAKE_TOUCH, x, y, 0);
        timer_mod(p->touch_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + MT_FRAME_NS);
    } else if (!p->touching && p->contact) {
        p->contact = false;
        timer_del(p->touch_timer);
        peer_lift_off(p, x, y);
        peer_send_mt(p, APPLE_MODERN_MT_STAGE_LINGER_IN_RANGE, x, y, MT_FRAME_NS);
        peer_send_mt(p, APPLE_MODERN_MT_STAGE_OUT_OF_RANGE, x, y, 2 * MT_FRAME_NS);
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
    p->gesture_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, peer_gesture_tick, p);
    object_property_add_str(OBJECT(dc), "x-touch", peer_x_touch_get,
                            peer_x_touch_set);
    apple_modern_dockchannel_set_peer(dc, peer_tx, p);
    apple_modern_dockchannel_set_arm_cb(dc, peer_arm, p);
    p->input = qemu_input_handler_register(DEVICE(dc), &peer_input_handler);
    qemu_input_handler_activate(p->input);
    return p;
}
