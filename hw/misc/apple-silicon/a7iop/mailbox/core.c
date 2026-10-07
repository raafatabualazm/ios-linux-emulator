/*
 * Apple A7IOP Mailbox.
 *
 * Copyright (c) 2023-2026 Visual Ehrmanntraut (VisualEhrmanntraut).
 * Copyright (c) 2023-2026 Christian Inci (chris-pcguy).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "block/aio.h"
#include "hw/irq.h"
#include "hw/misc/apple-silicon/a7iop/base.h"
#include "hw/misc/apple-silicon/a7iop/mailbox/core.h"
#include "hw/misc/apple-silicon/a7iop/mailbox/private.h"
#include "hw/misc/apple-silicon/a7iop/mailbox/trace.h"
#include "hw/misc/apple-silicon/a7iop/private.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/queue.h"

#define MAX_MESSAGE_COUNT (15)

/* ===== MBOXDIAG: bounded measurement instrumentation (diagnostic only) ===== */
#include "qemu/timer.h"

#define MBD_MAX_DEV 12
#define MBD_MAX_LINES 900

typedef struct MbdDev {
    char name[16];
    bool used;
    /* index 0: the iop object / A2I queue ; index 1: the ap object / I2A queue */
    uint64_t upd_status[2];
    uint64_t enq[2], deq[2];
    uint64_t uf_latch[2], uf_sticky[2];
    uint64_t mask_w[2];
    uint64_t pin_chg[4];                 /* transitions of the EXPORTED (ap object) pins */
    uint64_t ev;                         /* queue-affecting events */
    uint64_t stale_ep[2], stale_ep_line[2][4], stale_updates[2];
    uint64_t stale_ns_total[2], stale_ns_max[2], heals[2];
    uint64_t stale_ev_total[2];
    uint8_t stale_now[2];
    uint64_t stale_since_ns[2], stale_since_ev[2];
    const char *stale_cause[2];
    uint64_t heal_by_ctx[2][6];
} MbdDev;

static MbdDev mbd_devs[MBD_MAX_DEV];
static unsigned mbd_lines;
static int mbd_depth;
static const char *mbd_ctx = "other";
static const char *mbd_kind = "other";
static bool mbd_atexit_done;
static const char *const mbd_ctx_names[6] = { "send-a2i", "recv-a2i", "send-i2a",
                                              "recv-i2a", "mask", "reset" };

static FILE *mbd_fp;
static bool mbd_fp_tried;
static unsigned mbd_file_lines;

/* MBOX_DIAG_FULL_FANOUT=1: counterfactual that refreshes both objects on every update. */
static bool mbd_full_fanout(void)
{
    static int on = -1;

    if (on < 0) {
        on = getenv("MBOX_DIAG_FULL_FANOUT") != NULL;
    }
    return on;
}

static void mbd_log(const char *fmt, ...)
{
    va_list ap, ap2;

    if (!mbd_fp_tried) {
        const char *path = getenv("MBOX_DIAG_FILE");

        mbd_fp_tried = true;
        if (path) {
            mbd_fp = fopen(path, "a");
        }
    }
    va_start(ap, fmt);
    va_copy(ap2, ap);
    if (mbd_lines < MBD_MAX_LINES) {
        mbd_lines++;
        fputs("MBOXDIAG ", stderr);
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
    if (mbd_fp && mbd_file_lines < 6000) {
        mbd_file_lines++;
        fputs("MBOXDIAG ", mbd_fp);
        vfprintf(mbd_fp, fmt, ap2);
        fputc('\n', mbd_fp);
        fflush(mbd_fp);
    }
    va_end(ap2);
    va_end(ap);
}

static int mbd_idx(AppleA7IOPMailbox *s)
{
    return s == s->iop_mailbox ? 0 : 1;
}

static MbdDev *mbd_dev(AppleA7IOPMailbox *s)
{
    char name[16];
    const char *dash = strrchr(s->role, '-');
    size_t n = dash ? (size_t)(dash - s->role) : strlen(s->role);
    int i;

    if (n >= sizeof(name)) {
        n = sizeof(name) - 1;
    }
    memcpy(name, s->role, n);
    name[n] = 0;
    for (i = 0; i < MBD_MAX_DEV; i++) {
        if (mbd_devs[i].used && !strcmp(mbd_devs[i].name, name)) {
            return &mbd_devs[i];
        }
    }
    for (i = 0; i < MBD_MAX_DEV; i++) {
        if (!mbd_devs[i].used) {
            mbd_devs[i].used = true;
            memcpy(mbd_devs[i].name, name, n + 1);
            return &mbd_devs[i];
        }
    }
    return &mbd_devs[MBD_MAX_DEV - 1];
}

static uint8_t mbd_cached(AppleA7IOPMailbox *o)
{
    return (o->iop_nonempty ? 1 : 0) | (o->iop_empty ? 2 : 0) |
           (o->ap_nonempty ? 4 : 0) | (o->ap_empty ? 8 : 0);
}

/* The four line levels object o WOULD show if it were refreshed right now. */
static uint8_t mbd_expect(AppleA7IOPMailbox *o)
{
    AppleA7IOPMailbox *io = o->iop_mailbox, *ap = o->ap_mailbox;
    bool ie = QTAILQ_EMPTY(&io->inbox), ae = QTAILQ_EMPTY(&ap->inbox);
    uint32_t m = o->int_mask;

    return (((m & IOP_NONEMPTY) == 0 && !ie) || io->underflow ? 1 : 0) |
           (((m & IOP_EMPTY) == 0 && ie) ? 2 : 0) |
           (((m & AP_NONEMPTY) == 0 && !ae) || ap->underflow ? 4 : 0) |
           (((m & AP_EMPTY) == 0 && ae) ? 8 : 0);
}

static unsigned mbd_qlen(AppleA7IOPMailbox *q)
{
    unsigned n = 0;
    AppleA7IOPMessage *m;

    QTAILQ_FOREACH (m, &q->inbox, next) {
        n++;
    }
    return n;
}

static int mbd_ctx_index(void)
{
    for (int i = 0; i < 6; i++) {
        if (!strcmp(mbd_ctx, mbd_ctx_names[i])) {
            return i;
        }
    }
    return -1;
}

static void mbd_summary(MbdDev *d, const char *tag)
{
    mbd_log("sum %s dev=%s ev=%" PRIu64 " a2i_enq=%" PRIu64 " a2i_deq=%" PRIu64
            " i2a_enq=%" PRIu64 " i2a_deq=%" PRIu64 " uf_latch(i/a)=%" PRIu64
            "/%" PRIu64 " uf_sticky(i/a)=%" PRIu64 "/%" PRIu64
            " mask_w(i/a)=%" PRIu64 "/%" PRIu64 " pin_chg[iop_ne,iop_e,ap_ne,ap_e]=%"
            PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64,
            tag, d->name, d->ev, d->enq[0], d->deq[0], d->enq[1], d->deq[1],
            d->uf_latch[0], d->uf_latch[1], d->uf_sticky[0], d->uf_sticky[1],
            d->mask_w[0], d->mask_w[1], d->pin_chg[0], d->pin_chg[1],
            d->pin_chg[2], d->pin_chg[3]);
    for (int k = 0; k < 2; k++) {
        mbd_log("sum %s dev=%s %s stale_episodes=%" PRIu64 " by_line[iop_ne,iop_e,ap_ne,ap_e]=%"
                PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 " completed_updates_left_stale=%"
                PRIu64 " heals=%" PRIu64 " stale_ns_total=%" PRIu64 " stale_ns_max=%"
                PRIu64 " stale_events_total=%" PRIu64 " stale_now=0x%x heal_by_ctx[%s=%" PRIu64
                ",%s=%" PRIu64 ",%s=%" PRIu64 ",%s=%" PRIu64 ",%s=%" PRIu64 ",%s=%" PRIu64
                ",other=%" PRIu64 "]",
                tag, d->name, k == 0 ? "I-object(cache/cpu-irq)" : "A-object(EXPORTED)",
                d->stale_ep[k], d->stale_ep_line[k][0], d->stale_ep_line[k][1],
                d->stale_ep_line[k][2], d->stale_ep_line[k][3], d->stale_updates[k],
                d->heals[k], d->stale_ns_total[k], d->stale_ns_max[k],
                d->stale_ev_total[k], d->stale_now[k],
                mbd_ctx_names[0], d->heal_by_ctx[k][0], mbd_ctx_names[1], d->heal_by_ctx[k][1],
                mbd_ctx_names[2], d->heal_by_ctx[k][2], mbd_ctx_names[3], d->heal_by_ctx[k][3],
                mbd_ctx_names[4], d->heal_by_ctx[k][4], mbd_ctx_names[5], d->heal_by_ctx[k][5],
                d->heals[k] - d->heal_by_ctx[k][0] - d->heal_by_ctx[k][1] -
                    d->heal_by_ctx[k][2] - d->heal_by_ctx[k][3] -
                    d->heal_by_ctx[k][4] - d->heal_by_ctx[k][5]);
    }
}

static void mbd_final(void)
{
    for (int i = 0; i < MBD_MAX_DEV; i++) {
        if (mbd_devs[i].used) {
            mbd_lines = 0;          /* the final summary always prints */
            mbd_file_lines = 0;
            mbd_summary(&mbd_devs[i], "FINAL");
        }
    }
}

static void mbd_touch(void)
{
    if (!mbd_atexit_done) {
        mbd_atexit_done = true;
        atexit(mbd_final);
    }
}

/* Called when a top-level update_irq() has finished propagating. */
static void mbd_check(AppleA7IOPMailbox *s)
{
    MbdDev *d = mbd_dev(s);
    AppleA7IOPMailbox *obj[2] = { s->iop_mailbox, s->ap_mailbox };
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    for (int k = 0; k < 2; k++) {
        uint8_t diff = mbd_expect(obj[k]) ^ mbd_cached(obj[k]);

        if (diff) {
            d->stale_updates[k]++;
        }
        if (diff && !d->stale_now[k]) {
            d->stale_ep[k]++;
            for (int l = 0; l < 4; l++) {
                if (diff & (1 << l)) {
                    d->stale_ep_line[k][l]++;
                }
            }
            d->stale_since_ns[k] = now;
            d->stale_since_ev[k] = d->ev;
            d->stale_cause[k] = mbd_ctx;
            if (d->stale_ep[k] <= 10) {
                mbd_log("STALE-BEGIN dev=%s obj=%s cause=%s diff=0x%x expect=0x%x cached=0x%x "
                        "qa2i=%u qi2a=%u uf_i=%d uf_a=%d mask_ap=0x%x mask_iop=0x%x t=%" PRIu64,
                        d->name, k == 0 ? "I" : "A", mbd_ctx, diff, mbd_expect(obj[k]),
                        mbd_cached(obj[k]), mbd_qlen(s->iop_mailbox), mbd_qlen(s->ap_mailbox),
                        s->iop_mailbox->underflow, s->ap_mailbox->underflow,
                        s->ap_mailbox->int_mask, s->iop_mailbox->int_mask, now);
            }
        } else if (!diff && d->stale_now[k]) {
            uint64_t dur = now - d->stale_since_ns[k];
            int ci = mbd_ctx_index();

            d->heals[k]++;
            if (ci >= 0) {
                d->heal_by_ctx[k][ci]++;
            }
            d->stale_ns_total[k] += dur;
            if (dur > d->stale_ns_max[k]) {
                d->stale_ns_max[k] = dur;
            }
            d->stale_ev_total[k] += d->ev - d->stale_since_ev[k];
            if (d->heals[k] <= 10) {
                mbd_log("STALE-END dev=%s obj=%s begun_by=%s healed_by=%s dur_ns=%" PRIu64
                        " queue_events_during=%" PRIu64,
                        d->name, k == 0 ? "I" : "A", d->stale_cause[k], mbd_ctx, dur,
                        d->ev - d->stale_since_ev[k]);
            }
        }
        d->stale_now[k] = diff;
    }
}

static void mbd_queue_event(AppleA7IOPMailbox *q, bool enq)
{
    MbdDev *d = mbd_dev(q);
    int k = mbd_idx(q);

    mbd_touch();
    mbd_kind = enq ? (k == 0 ? "send-a2i" : "send-i2a") : (k == 0 ? "recv-a2i" : "recv-i2a");
    if (enq) {
        d->enq[k]++;
    } else {
        d->deq[k]++;
    }
    d->ev++;
}

static void mbd_post_event(AppleA7IOPMailbox *q)
{
    MbdDev *d = mbd_dev(q);

    if (d->ev <= 48) {
        mbd_log("EVT dev=%s n=%" PRIu64 " kind=%s qa2i=%u qi2a=%u A.cache=0x%x A.expect=0x%x "
                "I.cache=0x%x I.expect=0x%x", d->name, d->ev, mbd_kind, mbd_qlen(q->iop_mailbox),
                mbd_qlen(q->ap_mailbox), mbd_cached(q->ap_mailbox), mbd_expect(q->ap_mailbox),
                mbd_cached(q->iop_mailbox), mbd_expect(q->iop_mailbox));
    }
    if (d->ev <= 4 || (d->ev & (d->ev - 1)) == 0 || d->ev % 512 == 0) {
        mbd_summary(d, "ev");
    }
}
/* ===== end MBOXDIAG ===== */

#define CTRL_ENABLE BIT(0)
#define CTRL_FULL BIT(16)
#define CTRL_EMPTY BIT(17)
#define CTRL_OVERFLOW BIT(18)
#define CTRL_UNDERFLOW BIT(19)
#define CTRL_COUNT_SHIFT (20)
#define CTRL_COUNT_MASK (MAX_MESSAGE_COUNT << CTRL_COUNT_SHIFT)
#define CTRL_COUNT(v) (((v) << CTRL_COUNT_SHIFT) & CTRL_COUNT_MASK)

static bool is_interrupt_enabled(AppleA7IOPMailbox *s, uint32_t status)
{
    if (!s->sepd_enabled) {
        // this workaround, just like the others, also seems to have the
        // side-effect of reducing the amount of timer0 interrupts, at least
        // under 18.5.
        return false;
    }
    if ((status & 0xF0000) == 0x10000 &&
        (s->glb_cfg & KIC_GLB_CFG_EXT_INT_EN) != 0) {
        uint32_t interrupt = status & 0x7F;
        int interrupt_group = interrupt / 32;
        // assert_cmpuint(interrupt_group, <, 4);
        uint32_t interrupt_enabled =
            s->interrupts_enabled[interrupt_group] & BIT(interrupt % 32);
        if (interrupt_enabled) {
            // if (status == INTERRUPT_SEP_MANUAL_TIMER) {
            //     // if timer0 or timer1 (maybe only timer0) unmasked, possible workaround for sepfw 18.5 exception.c:69, and it might not massively change the timer0 [sic] behavior, but only slightly
            //     // this approach doesn't fix 18.5
            //     if (!s->timer0_masked || !s->timer1_masked)
            //         return false;
            // }
            return true;
        }
    } else if (status == IRQ_IOP_NONEMPTY) {
        if (s->iop_nonempty) {
            return true;
        }
    } else if (status == IRQ_IOP_EMPTY) {
        if (s->iop_empty) {
            return true;
        }
    } else if (status == IRQ_AP_NONEMPTY) {
        if (s->ap_nonempty) {
            return true;
        }
    } else if (status == IRQ_AP_EMPTY) {
        if (s->ap_empty) {
            return true;
        }
    } else if (status == IRQ_SEP_TIMER0) {
        // fprintf(stderr, "%s: IRQ_SEP_TIMER0: status: 0x%x timer0_enabled: 0x%x timer0_masked: 0x%x\n", __func__, status, s->timer0_enabled, s->timer0_masked);
        // if (s->interrupts_enabled[0] & BIT(8)) {
        //     // if manual_timer unmasked, possible workaround for sepfw 18.5 exception.c:69, but it changes the timer0 [sic] behavior massively
        //     // this approach breaks 14beta5
        //     return false;
        // } else
        if ((s->timer0_enabled & REG_KIC_TMR_EN_MASK) == REG_KIC_TMR_EN_MASK &&
            (s->timer0_masked & REG_KIC_TMR_INT_MASK_MASK) == 0) {
            return true;
        }
    } else if (status == IRQ_SEP_TIMER1) {
        // if (s->interrupts_enabled[0] & BIT(8)) {
        //     // if manual_timer unmasked, possible workaround for sepfw 18.5 exception.c:69, but it changes the timer0 [sic] behavior massively
        //     // also doing it for timer1 just to make sure
        //     // this approach breaks 14beta5
        //     return false;
        // } else
        if ((s->timer1_enabled & REG_KIC_TMR_EN_MASK) == REG_KIC_TMR_EN_MASK &&
            (s->timer1_masked & REG_KIC_TMR_INT_MASK_MASK) == 0) {
            return true;
        }
    } else {
        return true;
    }
    return false;
}


static bool apple_mbox_interrupt_status_empty(AppleA7IOPMailbox *s)
{
    AppleA7IOPInterruptStatusMessage *msg;

    QTAILQ_FOREACH (msg, &s->interrupt_status, entry) {
        if (is_interrupt_enabled(s, msg->status)) {
            return false;
        }
    }

    return true;
}

static inline bool iop_empty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & IOP_EMPTY) == 0;
}

static inline bool iop_nonempty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & IOP_NONEMPTY) == 0;
}

static inline bool ap_empty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & AP_EMPTY) == 0;
}

static inline bool ap_nonempty_is_unmasked(uint32_t int_mask)
{
    return (int_mask & AP_NONEMPTY) == 0;
}

void apple_a7iop_mailbox_update_irq_status(AppleA7IOPMailbox *s)
{
    bool iop_empty;
    bool ap_empty;
    bool iop_underflow;
    bool ap_underflow;
    bool iop_nonempty_unmasked;
    bool iop_empty_unmasked;
    bool ap_nonempty_unmasked;
    bool ap_empty_unmasked;

    uint8_t mbd_old = mbd_cached(s);

    mbd_touch();
    mbd_dev(s)->upd_status[mbd_idx(s)]++;
    iop_empty = QTAILQ_EMPTY(&s->iop_mailbox->inbox);
    ap_empty = QTAILQ_EMPTY(&s->ap_mailbox->inbox);
    iop_underflow = s->iop_mailbox->underflow;
    ap_underflow = s->ap_mailbox->underflow;
    iop_nonempty_unmasked = iop_nonempty_is_unmasked(s->int_mask);
    iop_empty_unmasked = iop_empty_is_unmasked(s->int_mask);
    ap_nonempty_unmasked = ap_nonempty_is_unmasked(s->int_mask);
    ap_empty_unmasked = ap_empty_is_unmasked(s->int_mask);

    trace_apple_a7iop_mailbox_update_irq(
        s->role, iop_empty, ap_empty, !iop_nonempty_unmasked,
        !iop_empty_unmasked, !ap_nonempty_unmasked, !ap_empty_unmasked);


    // SEP:
    // 0x65: inbox/IOP overflow
    // 0x66: inbox/IOP underflow
    // 0x67: outbox/AP overflow
    // 0x68: outbox/AP underflow

    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_IOP_NONEMPTY],
                 (iop_nonempty_unmasked && !iop_empty) || iop_underflow);
    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_IOP_EMPTY],
                 iop_empty_unmasked && iop_empty);

    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_AP_NONEMPTY],
                 (ap_nonempty_unmasked && !ap_empty) || ap_underflow);
    qemu_set_irq(s->irqs[APPLE_A7IOP_IRQ_AP_EMPTY],
                 ap_empty_unmasked && ap_empty);

    s->iop_nonempty = (iop_nonempty_unmasked && !iop_empty) || iop_underflow;
    s->iop_empty = iop_empty_unmasked && iop_empty;
    s->ap_nonempty = (ap_nonempty_unmasked && !ap_empty) || ap_underflow;
    s->ap_empty = ap_empty_unmasked && ap_empty;
    if (mbd_idx(s) == 1) {
        uint8_t chg = mbd_old ^ mbd_cached(s);

        for (int l = 0; l < 4; l++) {
            if (chg & (1 << l)) {
                mbd_dev(s)->pin_chg[l]++;
            }
        }
    }
}

void apple_a7iop_mailbox_update_irq(AppleA7IOPMailbox *s)
{
    mbd_depth++;
    apple_a7iop_mailbox_update_irq_status(s);

    bool sep_cpu_irq_raised =
        s->iop_nonempty || s->iop_empty || s->ap_nonempty || s->ap_empty;
    sep_cpu_irq_raised |= !apple_mbox_interrupt_status_empty(s);
    if (!strcmp(s->role, "SEP-iop")) {
        qemu_set_irq(s->sep_cpu_irq, sep_cpu_irq_raised);
    }
    smp_mb();
    if (!strcmp(s->role, "SEP-ap")) {
        apple_a7iop_mailbox_update_irq(s->iop_mailbox);
    } else if (mbd_full_fanout() && mbd_depth == 1) {
        /* MBOXDIAG counterfactual: refresh the peer object too, whatever the role. */
        AppleA7IOPMailbox *peer = s == s->iop_mailbox ? s->ap_mailbox : s->iop_mailbox;

        if (peer != s) {
            apple_a7iop_mailbox_update_irq(peer);
        }
    }
    if (--mbd_depth == 0) {
        mbd_check(s);
        mbd_ctx = "other";
    }
}

bool apple_a7iop_mailbox_is_empty(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);

    return s->underflow || QTAILQ_EMPTY(&s->inbox);
}

static void apple_a7iop_mailbox_send(AppleA7IOPMailbox *s,
                                     AppleA7IOPMessage *msg)
{
    assert_nonnull(msg);

    QEMU_LOCK_GUARD(&s->lock);

    trace_apple_a7iop_mailbox_send(s->role, ldq_le_p(msg->data),
                                   ldq_le_p(msg->data + sizeof(uint64_t)));

    QTAILQ_INSERT_TAIL(&s->inbox, msg, next);
    s->count++;
    mbd_queue_event(s, true);
    mbd_ctx = mbd_idx(s) == 0 ? "send-a2i" : "send-i2a";
    apple_a7iop_mailbox_update_irq(s);
    mbd_post_event(s);

    if (s->handle_messages_bh != NULL) {
        qemu_bh_schedule(s->handle_messages_bh);
    }
}

void apple_a7iop_mailbox_send_ap(AppleA7IOPMailbox *s, AppleA7IOPMessage *msg)
{
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        if (!s->ap_dir_en) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: %s direction not enabled.\n",
                          __FUNCTION__, s->role);
            return;
        }
    }

    apple_a7iop_mailbox_send(s->ap_mailbox, msg);
}

void apple_a7iop_mailbox_send_iop(AppleA7IOPMailbox *s, AppleA7IOPMessage *msg)
{
    WITH_QEMU_LOCK_GUARD(&s->lock)
    {
        if (!s->iop_dir_en) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: %s direction not enabled.\n",
                          __FUNCTION__, s->role);
            return;
        }
    }

    apple_a7iop_mailbox_send(s->iop_mailbox, msg);
}

AppleA7IOPMessage *apple_a7iop_inbox_peek(AppleA7IOPMailbox *s)
{
    return QTAILQ_FIRST(&s->inbox);
}

static AppleA7IOPMessage *apple_a7iop_mailbox_recv(AppleA7IOPMailbox *s)
{
    AppleA7IOPMessage *msg;

    if (s->underflow) {
        MbdDev *d = mbd_dev(s);

        d->uf_sticky[mbd_idx(s)]++;
        if (d->uf_sticky[mbd_idx(s)] <= 8) {
            mbd_log("UF-STICKY-HIT dev=%s queue=%s qlen=%u (receive refused: underflow latched)",
                    d->name, mbd_idx(s) == 0 ? "A2I" : "I2A", mbd_qlen(s));
        }
        return NULL;
    }

    msg = QTAILQ_FIRST(&s->inbox);
    if (msg == NULL) {
        MbdDev *d = mbd_dev(s);

        mbd_touch();
        d->uf_latch[mbd_idx(s)]++;
        mbd_log("UF-LATCH dev=%s queue=%s t=%" PRIu64 " (receive on empty queue)",
                d->name, mbd_idx(s) == 0 ? "A2I" : "I2A",
                (uint64_t)qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        mbd_ctx = mbd_idx(s) == 0 ? "recv-a2i" : "recv-i2a";
        s->underflow = true;
        qemu_log_mask(LOG_GUEST_ERROR, "%s: %s underflowed.\n", __FUNCTION__,
                      s->role);
        apple_a7iop_mailbox_update_irq(s);
        return NULL;
    }

    QTAILQ_REMOVE(&s->inbox, msg, next);
    stl_le_p(msg->data + 0xC, CTRL_COUNT(s->count));
    trace_apple_a7iop_mailbox_recv(s->role, ldq_le_p(msg->data),
                                   ldq_le_p(msg->data + sizeof(uint64_t)));
    s->count--;
    mbd_queue_event(s, false);
    mbd_ctx = mbd_idx(s) == 0 ? "recv-a2i" : "recv-i2a";
    apple_a7iop_mailbox_update_irq(s);
    mbd_post_event(s);

    return msg;
}

AppleA7IOPMessage *apple_a7iop_mailbox_recv_iop(AppleA7IOPMailbox *s)
{
    AppleA7IOPMessage *msg;

    if (!s->iop_dir_en) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: %s direction not enabled.\n",
                      __FUNCTION__, s->role);
        return NULL;
    }

    msg = apple_a7iop_mailbox_recv(s->iop_mailbox);

    return msg;
}

AppleA7IOPMessage *apple_a7iop_mailbox_recv_ap(AppleA7IOPMailbox *s)
{
    AppleA7IOPMessage *msg;

    if (!s->ap_dir_en) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: %s direction not enabled.\n",
                      __FUNCTION__, s->role);
        return NULL;
    }

    msg = apple_a7iop_mailbox_recv(s->ap_mailbox);

    return msg;
}

uint32_t apple_a7iop_mailbox_get_int_mask(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);

    return s->int_mask;
}

void apple_a7iop_mailbox_set_int_mask(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);

    s->int_mask |= value;
    mbd_dev(s)->mask_w[mbd_idx(s)]++;
    if (mbd_dev(s)->mask_w[0] + mbd_dev(s)->mask_w[1] <= 60) {
        mbd_log("MASK-SET dev=%s obj=%s value=0x%x new_mask=0x%x", mbd_dev(s)->name,
                mbd_idx(s) == 0 ? "I" : "A", value, s->int_mask);
    }
    mbd_ctx = "mask";
    apple_a7iop_mailbox_update_irq(s);
}

void apple_a7iop_mailbox_clear_int_mask(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);

    s->int_mask &= ~value;
    mbd_dev(s)->mask_w[mbd_idx(s)]++;
    if (mbd_dev(s)->mask_w[0] + mbd_dev(s)->mask_w[1] <= 60) {
        mbd_log("MASK-CLR dev=%s obj=%s value=0x%x new_mask=0x%x", mbd_dev(s)->name,
                mbd_idx(s) == 0 ? "I" : "A", value, s->int_mask);
    }
    mbd_ctx = "mask";
    apple_a7iop_mailbox_update_irq(s);
}

static inline uint32_t apple_a7iop_mailbox_ctrl(AppleA7IOPMailbox *s)
{
    if (s->underflow) {
        return CTRL_UNDERFLOW;
    }

    return (s->count >= MAX_MESSAGE_COUNT ? CTRL_FULL : 0) |
           (QTAILQ_EMPTY(&s->inbox) ? CTRL_EMPTY : 0) |
           CTRL_COUNT(MIN(s->count, MAX_MESSAGE_COUNT));
}

uint32_t apple_a7iop_mailbox_get_iop_ctrl(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);

    return (s->iop_dir_en ? CTRL_ENABLE : 0) |
           apple_a7iop_mailbox_ctrl(s->iop_mailbox);
}

void apple_a7iop_mailbox_set_iop_ctrl(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);

    s->iop_dir_en = (value & CTRL_ENABLE) != 0;
}

uint32_t apple_a7iop_mailbox_get_ap_ctrl(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);

    return (s->ap_dir_en ? CTRL_ENABLE : 0) |
           apple_a7iop_mailbox_ctrl(s->ap_mailbox);
}

void apple_a7iop_mailbox_set_ap_ctrl(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);

    s->ap_dir_en = (value & CTRL_ENABLE) != 0;
}

void apple_a7iop_interrupt_status_push(AppleA7IOPMailbox *s, uint32_t status)
{
    AppleA7IOPInterruptStatusMessage *msg;

#if 1
    QTAILQ_FOREACH (msg, &s->interrupt_status, entry) {
        if (msg->status == status) {
            apple_a7iop_mailbox_update_irq(s);
            return;
        }
    }
#endif
    // DON'T TEST FOR interrupts_enabled DURING PUSH!!
    // and maybe don't push when the status is already in the list
    msg = g_new0(struct AppleA7IOPInterruptStatusMessage, 1);
    msg->status = status;
    QTAILQ_INSERT_TAIL(&s->interrupt_status, msg, entry);
    apple_a7iop_mailbox_update_irq(s);
}

uint32_t apple_a7iop_interrupt_status_pop(AppleA7IOPMailbox *s)
{
    uint32_t ret = 0;
    AppleA7IOPInterruptStatusMessage *msg, *preferred_msg = NULL;
    uint32_t interrupt_group_msg = 0, interrupt_group_preferred_msg = 0;

    // order should be 0x4, 0x7, 0x1, but 0x4 shouldn't be handled here at all.

    QTAILQ_FOREACH (msg, &s->interrupt_status, entry) {
        interrupt_group_msg = (msg->status >> 16) & 0x7;
        if (is_interrupt_enabled(s, msg->status)) {
            if (preferred_msg == NULL ||
                (interrupt_group_msg == interrupt_group_preferred_msg &&
                 msg->status < preferred_msg->status) ||
                (interrupt_group_msg != interrupt_group_preferred_msg &&
                 interrupt_group_msg == 0x7)) {
                preferred_msg = msg;
                interrupt_group_preferred_msg = interrupt_group_msg;
            }
        }
    }

    if (preferred_msg) {
        QTAILQ_REMOVE(&s->interrupt_status, preferred_msg, entry);
        ret = preferred_msg->status;
        g_free(preferred_msg);
    }

    apple_a7iop_mailbox_update_irq(s);

    return ret;
}

uint32_t apple_a7iop_mailbox_read_interrupt_status(AppleA7IOPMailbox *s)
{
    QEMU_LOCK_GUARD(&s->lock);
    // the order should be: 0x4..., 0x7..., 0x1...
    AppleA7IOPMailbox *a7iop_mbox = s->iop_mailbox;
    uint32_t interrupt_status;
    if (a7iop_mbox->iop_nonempty) {
        interrupt_status = IRQ_IOP_NONEMPTY;
        a7iop_mbox->int_mask |= IOP_NONEMPTY;
    } else if (a7iop_mbox->iop_empty) {
        interrupt_status = IRQ_IOP_EMPTY;
        a7iop_mbox->int_mask |= IOP_EMPTY;
    } else if (a7iop_mbox->ap_nonempty) {
        interrupt_status = IRQ_AP_NONEMPTY;
        a7iop_mbox->int_mask |= AP_NONEMPTY;
    } else if (a7iop_mbox->ap_empty) {
        interrupt_status = IRQ_AP_EMPTY;
        a7iop_mbox->int_mask |= AP_EMPTY;
    } else if ((interrupt_status = apple_a7iop_interrupt_status_pop(s)) != 0) {
        if ((interrupt_status & 0xf0000) == 0x10000) {
            uint32_t interrupt = interrupt_status & 0x7F;
            int interrupt_group = interrupt / 32;
            // assert_cmpuint(interrupt_group, <, 4);
            a7iop_mbox->interrupts_enabled[interrupt_group] &=
                ~(BIT(interrupt % 32));
        } else if (interrupt_status == IRQ_IOP_NONEMPTY) {
            a7iop_mbox->int_mask |= IOP_NONEMPTY;
        } else if (interrupt_status == IRQ_IOP_EMPTY) {
            a7iop_mbox->int_mask |= IOP_EMPTY;
        } else if (interrupt_status == IRQ_AP_NONEMPTY) {
            a7iop_mbox->int_mask |= AP_NONEMPTY;
        } else if (interrupt_status == IRQ_AP_EMPTY) {
            a7iop_mbox->int_mask |= AP_EMPTY;
        } else if (interrupt_status == IRQ_MAILBOX_UNKN0_NONEMPTY) {
            a7iop_mbox->int_mask |= MAILBOX_MASKBIT_UNKN0_NONEMPTY;
        } else if (interrupt_status == IRQ_MAILBOX_UNKN0_EMPTY) {
            a7iop_mbox->int_mask |= MAILBOX_MASKBIT_UNKN0_EMPTY;
        } else if (interrupt_status == IRQ_MAILBOX_UNKN1_NONEMPTY) {
            a7iop_mbox->int_mask |= MAILBOX_MASKBIT_UNKN1_NONEMPTY;
        } else if (interrupt_status == IRQ_MAILBOX_UNKN1_EMPTY) {
            a7iop_mbox->int_mask |= MAILBOX_MASKBIT_UNKN1_EMPTY;
        } else if (interrupt_status == IRQ_MAILBOX_UNKN2_NONEMPTY) {
            a7iop_mbox->int_mask |= MAILBOX_MASKBIT_UNKN2_NONEMPTY;
        } else if (interrupt_status == IRQ_MAILBOX_UNKN2_EMPTY) {
            a7iop_mbox->int_mask |= MAILBOX_MASKBIT_UNKN2_EMPTY;
        } else if (interrupt_status == IRQ_MAILBOX_UNKN3_NONEMPTY) {
            a7iop_mbox->int_mask |= MAILBOX_MASKBIT_UNKN3_NONEMPTY;
        } else if (interrupt_status == IRQ_MAILBOX_UNKN3_EMPTY) {
            a7iop_mbox->int_mask |= MAILBOX_MASKBIT_UNKN3_EMPTY;
        } else if (interrupt_status == IRQ_SEP_TIMER0) {
            a7iop_mbox->timer0_masked |= REG_KIC_TMR_INT_MASK_MASK;
        } else if (interrupt_status == IRQ_SEP_TIMER1) {
            a7iop_mbox->timer1_masked |= REG_KIC_TMR_INT_MASK_MASK;
        }
    }
    apple_a7iop_mailbox_update_irq(s);
    return interrupt_status;
}

static void apple_a7iop_gpio_timer0(void *opaque, int n, int level)
{
    AppleA7IOPMailbox *s = opaque;
    bool val = !!level;
    assert(n == 0);
    // fprintf(stderr, "%s: level: %d\n", __func__, level);
    // val can and will be false, keep that in mind. no idea what to do then.
    // maybe that's qemu's way of saying that the hardware can't keep up, that
    // it's not confirming the interrupts fast enough.
    if (!val) {
        return;
    }
    QEMU_LOCK_GUARD(&s->lock);
    // DON'T also do the checks here, only do them in interrupt_status_pop
    apple_a7iop_interrupt_status_push(s, IRQ_SEP_TIMER0);
}

static void apple_a7iop_gpio_timer1(void *opaque, int n, int level)
{
    AppleA7IOPMailbox *s = opaque;
    bool val = !!level;
    assert(n == 0);
    // fprintf(stderr, "%s: level: %d\n", __func__, level);
    // val can and will be false, keep that in mind. no idea what to do then.
    // maybe that's qemu's way of saying that the hardware can't keep up, that
    // it's not confirming the interrupts fast enough.
    if (!val) {
        return;
    }
    QEMU_LOCK_GUARD(&s->lock);
    // DON'T also do the checks here, only do them in interrupt_status_pop
    apple_a7iop_interrupt_status_push(s, IRQ_SEP_TIMER1);
}

AppleA7IOPMailbox *apple_a7iop_mailbox_new(const char *role,
                                           AppleA7IOPVersion version,
                                           AppleA7IOPMailbox *iop_mailbox,
                                           AppleA7IOPMailbox *ap_mailbox,
                                           void *opaque,
                                           QEMUBHFunc *handle_messages_func)
{
    DeviceState *dev;
    SysBusDevice *sbd;
    AppleA7IOPMailbox *s;
    int i;
    char name[128] = { 0 };

    dev = qdev_new(TYPE_APPLE_A7IOP_MAILBOX);
    sbd = SYS_BUS_DEVICE(dev);
    s = APPLE_A7IOP_MAILBOX(dev);

    s->role = g_strdup(role);
    s->iop_mailbox = iop_mailbox ? iop_mailbox : s;
    s->ap_mailbox = ap_mailbox ? ap_mailbox : s;
    if (handle_messages_func != NULL) {
        s->handle_messages_bh =
            aio_bh_new_guarded(qemu_get_aio_context(), handle_messages_func,
                               opaque, &dev->mem_reentrancy_guard);
    }
    QTAILQ_INIT(&s->inbox);
    QTAILQ_INIT(&s->interrupt_status);
    qemu_mutex_init(&s->lock);
    for (i = 0; i < APPLE_A7IOP_IRQ_MAX; i++) {
        sysbus_init_irq(sbd, s->irqs + i);
    }
    qdev_init_gpio_out_named(dev, &s->sep_cpu_irq, APPLE_A7IOP_SEP_CPU_IRQ, 1);

    snprintf(name, sizeof(name), TYPE_APPLE_A7IOP_MAILBOX ".%s.regs", s->role);

    switch (version) {
    case APPLE_A7IOP_V2:
        apple_a7iop_mailbox_init_mmio_v2(s, name);
        break;
    case APPLE_A7IOP_V4:
        apple_a7iop_mailbox_init_mmio_v4(s, name);
        break;
    case APPLE_A7IOP_V6:
        apple_a7iop_mailbox_init_mmio_v6(s, name);
        break;
    }

    sysbus_init_mmio(sbd, &s->mmio);

    if (!strcmp(s->role, "SEP-iop")) {
        qdev_init_gpio_in_named(DEVICE(s), apple_a7iop_gpio_timer0,
                                APPLE_A7IOP_SEP_GPIO_TIMER0, 1);
        qdev_init_gpio_in_named(DEVICE(s), apple_a7iop_gpio_timer1,
                                APPLE_A7IOP_SEP_GPIO_TIMER1, 1);
    }

    return s;
}

static void apple_a7iop_mailbox_reset(DeviceState *dev)
{
    AppleA7IOPMailbox *s;
    AppleA7IOPMessage *msg;
    AppleA7IOPMessage *msg_next;
    AppleA7IOPInterruptStatusMessage *intr_status_msg;
    AppleA7IOPInterruptStatusMessage *intr_status_msg_next;
    int i;

    s = APPLE_A7IOP_MAILBOX(dev);

    QEMU_LOCK_GUARD(&s->lock);

    mbd_touch();
    mbd_log("RESET-ENTER role=%s qa2i=%u qi2a=%u uf_i=%d uf_a=%d int_mask_before=0x%x "
            "cache_before=0x%x", s->role, mbd_qlen(s->iop_mailbox), mbd_qlen(s->ap_mailbox),
            s->iop_mailbox->underflow, s->ap_mailbox->underflow, s->int_mask, mbd_cached(s));

    assert_false(s->iop_mailbox == s->ap_mailbox);

    s->count = 0;
    s->iop_dir_en = true;
    s->ap_dir_en = true;
    s->underflow = false;
    memset(s->iop_recv_reg, 0, sizeof(s->iop_recv_reg));
    memset(s->ap_recv_reg, 0, sizeof(s->ap_recv_reg));
    memset(s->iop_send_reg, 0, sizeof(s->iop_send_reg));
    memset(s->ap_send_reg, 0, sizeof(s->ap_send_reg));

    QTAILQ_FOREACH_SAFE (msg, &s->inbox, next, msg_next) {
        QTAILQ_REMOVE(&s->inbox, msg, next);
        g_free(msg);
    }

    QTAILQ_FOREACH_SAFE (intr_status_msg, &s->interrupt_status, entry,
                         intr_status_msg_next) {
        QTAILQ_REMOVE(&s->interrupt_status, intr_status_msg, entry);
        g_free(intr_status_msg);
    }

    for (i = 0; i < ARRAY_SIZE(s->interrupts_enabled); i++) {
        s->interrupts_enabled[i] = 0;
    }

    s->iop_nonempty = 0;
    s->iop_empty = 0;
    s->ap_nonempty = 0;
    s->ap_empty = 0;
    s->glb_cfg = 0;
    s->timer0_enabled = 0;
    s->timer1_enabled = 0;
    s->timer0_masked = 0;
    s->timer1_masked = 0;
    s->sepd_enabled = 0;
    apple_a7iop_mailbox_update_irq_status(s);
    if (mbd_full_fanout()) {
        /* counterfactual: a reset of either object re-derives the peer's lines too */
        apple_a7iop_mailbox_update_irq_status(s == s->iop_mailbox ? s->ap_mailbox :
                                                                    s->iop_mailbox);
    }
    mbd_ctx = "reset";
    mbd_check(s);
    mbd_ctx = "other";
    mbd_log("RESET-EXIT role=%s exported_levels=0x%x (I-object cache 0x%x, A-object cache 0x%x)",
            s->role, mbd_cached(s->ap_mailbox), mbd_cached(s->iop_mailbox),
            mbd_cached(s->ap_mailbox));
}

const VMStateDescription vmstate_apple_a7iop_message = {
    .name = "Apple A7IOP Message State",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT8_ARRAY(data, AppleA7IOPMessage, 16),
            VMSTATE_END_OF_LIST(),
        }
};

static const VMStateDescription vmstate_apple_a7iop_int_status_message = {
    .name = "Apple A7IOP Interrupt Status Message State",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT32(status, AppleA7IOPInterruptStatusMessage),
            VMSTATE_END_OF_LIST(),
        }
};

static const VMStateDescription vmstate_apple_a7iop_mailbox = {
    .name = "Apple A7IOP Mailbox State",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_APPLE_A7IOP_MESSAGE(inbox, AppleA7IOPMailbox),
            VMSTATE_QTAILQ_V(interrupt_status, AppleA7IOPMailbox, 0,
                             vmstate_apple_a7iop_int_status_message,
                             AppleA7IOPInterruptStatusMessage, entry),
            VMSTATE_UINT32(count, AppleA7IOPMailbox),
            VMSTATE_BOOL(iop_dir_en, AppleA7IOPMailbox),
            VMSTATE_BOOL(ap_dir_en, AppleA7IOPMailbox),
            VMSTATE_BOOL(underflow, AppleA7IOPMailbox),
            VMSTATE_UINT32(int_mask, AppleA7IOPMailbox),
            VMSTATE_UINT8_ARRAY(iop_recv_reg, AppleA7IOPMailbox, 16),
            VMSTATE_UINT8_ARRAY(ap_recv_reg, AppleA7IOPMailbox, 16),
            VMSTATE_UINT8_ARRAY(iop_send_reg, AppleA7IOPMailbox, 16),
            VMSTATE_UINT8_ARRAY(ap_send_reg, AppleA7IOPMailbox, 16),
            VMSTATE_UINT32_ARRAY(interrupts_enabled, AppleA7IOPMailbox, 4),
            VMSTATE_BOOL(iop_nonempty, AppleA7IOPMailbox),
            VMSTATE_BOOL(iop_empty, AppleA7IOPMailbox),
            VMSTATE_BOOL(ap_nonempty, AppleA7IOPMailbox),
            VMSTATE_BOOL(ap_empty, AppleA7IOPMailbox),
            VMSTATE_UINT32(glb_cfg, AppleA7IOPMailbox),
            VMSTATE_UINT32(timer0_enabled, AppleA7IOPMailbox),
            VMSTATE_UINT32(timer1_enabled, AppleA7IOPMailbox),
            VMSTATE_UINT32(timer0_masked, AppleA7IOPMailbox),
            VMSTATE_UINT32(timer1_masked, AppleA7IOPMailbox),
            VMSTATE_UINT32(sepd_enabled, AppleA7IOPMailbox),
            VMSTATE_END_OF_LIST(),
        }
};

static void apple_a7iop_mailbox_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc;

    dc = DEVICE_CLASS(klass);

    dc->vmsd = &vmstate_apple_a7iop_mailbox;
    device_class_set_legacy_reset(dc, apple_a7iop_mailbox_reset);
    dc->desc = "Apple A7IOP Mailbox";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_a7iop_mailbox_info = {
    .name = TYPE_APPLE_A7IOP_MAILBOX,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleA7IOPMailbox),
    .class_init = apple_a7iop_mailbox_class_init,
};

static void apple_a7iop_mailbox_register_types(void)
{
    type_register_static(&apple_a7iop_mailbox_info);
}

type_init(apple_a7iop_mailbox_register_types);
