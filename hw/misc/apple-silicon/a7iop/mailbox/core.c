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

/* ==== MBOX-PROBE BEGIN: TEMPORARY measurement instrumentation (scratch, never commit) ====
 *
 * Observation only: no behaviour of the mailbox changes. Everything is bounded:
 * at most MBOX_PROBE_MAX_EV_LINES event lines per category plus a counter block
 * every ~10 s (only when something changed, capped), a final dump at exit, and
 * a "latest snapshot" file rewritten on every tick.
 *
 * Terminology (see the two known defects in regs-v6.c):
 *   A2I queue  = the inbox of the coprocessor-side mailbox object ("<X>-iop"),
 *                where mb->iop_mailbox == mb. Fed by the AP, drained by the IOP.
 *   I2A queue  = the inbox of the AP-side mailbox object ("<X>-ap"), where
 *                mb->ap_mailbox == mb. Fed by the IOP, drained by the AP.
 *   Exported lines = the four qemu_irq of the AP-side object (sysbus_pass_irq).
 *                The two that describe the A2I queue are IOP_NONEMPTY, IOP_EMPTY.
 *   Latched level  = ap->iop_nonempty / ap->iop_empty, set in the same function
 *                that calls qemu_set_irq, i.e. the level currently on the wire.
 *   Expected level = what update_irq_status(ap) would compute right now.
 *   STALE          = latched != expected, measured right after an A2I operation.
 */
#include "qemu/timer.h"
#include "hw/core/cpu.h"
#include "hw/intc/apple_aic.h"

#define MBOX_PROBE_MAX_MB 48
#define MBOX_PROBE_CAP_UNDERFLOW 60
#define MBOX_PROBE_CAP_STALE 40
#define MBOX_PROBE_CAP_STALE_ODD 80
#define MBOX_PROBE_CAP_COINC 20
#define MBOX_PROBE_CAP_AIC 40
#define MBOX_PROBE_CAP_EPISODE 60
#define MBOX_PROBE_CAP_MISC 40
#define MBOX_PROBE_MAX_DUMPS 300
#define MBOX_PROBE_TICK_MS 10000
#define MBOX_PROBE_LATEST \
    "/tmp/claude-1000/-home-kali-Desktop-Inferno-and-Darwin-VM/f5a0dd67-16db-41c1-85af-26719fda423c/scratchpad/mbox/probe-latest.txt"

typedef struct MboxProbe {
    AppleA7IOPMailbox *mb;
    /* per queue (every mailbox object) */
    uint64_t sent;              /* messages enqueued into this inbox */
    uint64_t recvd;             /* messages dequeued from this inbox */
    uint64_t to_nonempty;       /* empty -> non-empty transitions of this inbox */
    uint64_t to_empty;          /* non-empty -> empty transitions of this inbox */
    uint64_t max_depth;
    uint64_t recv_empty_latch;  /* receive on an empty queue: latches underflow */
    uint64_t recv_sticky_null;  /* receive that returned NULL: underflow already latched */
    uint64_t recv_dir_off;      /* receive refused: direction not enabled */
    uint64_t send_dir_off;      /* send dropped: direction not enabled */
    uint64_t resets;
    uint64_t resets_with_underflow;
    uint64_t update_calls;      /* update_irq_status() calls on this object */
    int64_t first_underflow_ms;
    /* A2I queue only (the coprocessor-side object): exported AP-side lines */
    uint64_t a2i_ops;           /* sends + receives on the A2I queue */
    uint64_t a2i_ops_ap_not_refreshed; /* ops after which the AP object was not refreshed */
    uint64_t ap_refreshes;      /* update_irq_status() calls on the paired AP object */
    uint64_t trans_ops;         /* A2I ops that changed empty/non-empty */
    uint64_t ops_ne_unmasked;   /* ops with IOP_NONEMPTY unmasked in the AP mask */
    uint64_t ops_e_unmasked;    /* ops with IOP_EMPTY unmasked in the AP mask */
    uint64_t stale_ops;         /* ops that left either exported line wrong */
    uint64_t stale_trans_ops;   /* ... of which were empty/non-empty transitions */
    uint64_t stale_ne_high, stale_ne_low; /* IOP_NONEMPTY: wrongly high / wrongly low */
    uint64_t stale_e_high, stale_e_low;   /* IOP_EMPTY:    wrongly high / wrongly low */
    bool ep_open;
    int64_t ep_start_ns;
    uint64_t ep_cur_ops;
    uint64_t ep_count, ep_by_refresh, ep_by_coincidence;
    uint64_t ep_ops_total, ep_ns_total, ep_ns_max;
    uint64_t refresh_unexpected_stale; /* self-check: stale at AP refresh with no open episode */
    uint64_t ap_refresh_changed_ne, ap_refresh_changed_e; /* line levels flipped by a heal */
    bool reset_pending;         /* the next AP-object refresh is the reset's own */
    /* v2: can the AP guest observe the exported lines at all? (AIC state) */
    uint64_t ops_deliv[4];      /* A2I ops with exported line k unmasked+routed in the AIC */
    uint64_t stale_deliv_ne, stale_deliv_e;   /* stale ops where that wrong line was deliverable */
    uint64_t stale_deliv_ne_trans, stale_deliv_e_trans;
    bool ever_deliv[4];
    uint64_t heal_deliv_ne, heal_deliv_e; /* heal flips while the line was deliverable */
    /* v2: the AP guest's own writes to the AP-side mailbox interrupt mask */
    uint64_t mask_set_calls, mask_clr_calls;
    uint32_t mask_or_ever;
} MboxProbe;

static MboxProbe mbox_probes[MBOX_PROBE_MAX_MB];
static int mbox_probe_n;
static int64_t mbox_probe_t0_ms;
static uint64_t mbox_probe_events;
static unsigned mbox_probe_dumps;
static unsigned mbox_probe_lines_underflow, mbox_probe_lines_stale,
    mbox_probe_lines_stale_odd, mbox_probe_lines_coinc,
    mbox_probe_lines_episode, mbox_probe_lines_aic, mbox_probe_lines_misc;
static GOnce mbox_probe_once = G_ONCE_INIT;
static int mbox_probe_overflow;
static uint64_t mbox_probe_last_sum;
static QEMUTimer *mbox_probe_timer;
G_LOCK_DEFINE_STATIC(mbox_probe);

static int64_t mbox_probe_now_ms(void)
{
    return qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - mbox_probe_t0_ms;
}

static int mbox_probe_cpu(void)
{
    return current_cpu ? (int)current_cpu->cpu_index : -1;
}

static const char *mbox_probe_dir(AppleA7IOPMailbox *mb)
{
    if (mb->iop_mailbox == mb) {
        return "A2I";
    }
    if (mb->ap_mailbox == mb) {
        return "I2A";
    }
    return "???";
}

/* Is exported line k of the AP object unmasked and routed in the AIC? */
static bool mbox_probe_line_deliverable(AppleA7IOPMailbox *ap, int k, int *n_out,
                                        bool *aic_found)
{
    qemu_irq irq = ap->irqs[k];
    AppleAICState *aic;
    int n;

    *aic_found = false;
    if (n_out) {
        *n_out = -1;
    }
    if (!irq || !irq->opaque) {
        return false;
    }
    aic = (AppleAICState *)object_dynamic_cast(OBJECT(irq->opaque),
                                               TYPE_APPLE_AIC);
    if (!aic || !aic->eir_mask || !aic->eir_dest) {
        return false;
    }
    *aic_found = true;
    n = irq->n;
    if (n_out) {
        *n_out = n;
    }
    if (n < 0 || (uint32_t)n >= aic->numIRQ) {
        return false;
    }
    return test_bit32(n, aic->eir_mask) == 0 && aic->eir_dest[n] != 0;
}

/* caller holds the probe lock */
static MboxProbe *mbox_probe_get_locked(AppleA7IOPMailbox *mb)
{
    int i;

    for (i = 0; i < mbox_probe_n; i++) {
        if (mbox_probes[i].mb == mb) {
            return &mbox_probes[i];
        }
    }
    if (mbox_probe_n >= MBOX_PROBE_MAX_MB) {
        mbox_probe_overflow++;
        return &mbox_probes[MBOX_PROBE_MAX_MB - 1];
    }
    memset(&mbox_probes[mbox_probe_n], 0, sizeof(MboxProbe));
    mbox_probes[mbox_probe_n].mb = mb;
    return &mbox_probes[mbox_probe_n++];
}

static void mbox_probe_print_one(FILE *f, MboxProbe *p)
{
    AppleA7IOPMailbox *mb = p->mb;
    AppleA7IOPMailbox *ap = mb->ap_mailbox;

    fprintf(f,
            "[mbox-probe] CNT role=%s dir=%s sent=%" PRIu64 " recvd=%" PRIu64
            " to_nonempty=%" PRIu64 " to_empty=%" PRIu64 " max_depth=%" PRIu64
            " depth_now=%u underflow_now=%d | UNDERFLOW recv_empty_latch=%" PRIu64
            " recv_sticky_null=%" PRIu64 " | DIROFF recv=%" PRIu64
            " send_dropped=%" PRIu64 " | resets=%" PRIu64
            " resets_with_underflow=%" PRIu64 " update_calls=%" PRIu64 "\n",
            mb->role, mbox_probe_dir(mb), p->sent, p->recvd, p->to_nonempty,
            p->to_empty, p->max_depth, mb->count, mb->underflow,
            p->recv_empty_latch, p->recv_sticky_null, p->recv_dir_off,
            p->send_dir_off, p->resets, p->resets_with_underflow,
            p->update_calls);
    if (mb->iop_mailbox == mb && ap != mb) {
        fprintf(f,
                "[mbox-probe] STALE role=%s a2i_ops=%" PRIu64
                " ap_not_refreshed_by_op=%" PRIu64 " ap_refreshes=%" PRIu64
                " trans_ops=%" PRIu64 " ops_with_IOP_NONEMPTY_unmasked=%" PRIu64
                " ops_with_IOP_EMPTY_unmasked=%" PRIu64 " stale_ops=%" PRIu64
                " stale_trans_ops=%" PRIu64 " ne_wrong_high=%" PRIu64
                " ne_wrong_low=%" PRIu64 " e_wrong_high=%" PRIu64
                " e_wrong_low=%" PRIu64 " | EPISODES n=%" PRIu64
                " healed_by_ap_refresh=%" PRIu64 " ended_by_coincidence=%" PRIu64
                " open=%d ops_total=%" PRIu64 " ms_total=%" PRIu64
                " ms_max=%" PRIu64 " heal_flipped_ne=%" PRIu64
                " heal_flipped_e=%" PRIu64 " selfcheck_unexpected=%" PRIu64
                "\n",
                mb->role, p->a2i_ops, p->a2i_ops_ap_not_refreshed,
                p->ap_refreshes, p->trans_ops, p->ops_ne_unmasked,
                p->ops_e_unmasked, p->stale_ops, p->stale_trans_ops,
                p->stale_ne_high, p->stale_ne_low, p->stale_e_high,
                p->stale_e_low, p->ep_count, p->ep_by_refresh,
                p->ep_by_coincidence, p->ep_open, p->ep_ops_total,
                p->ep_ns_total / 1000000, p->ep_ns_max / 1000000,
                p->ap_refresh_changed_ne, p->ap_refresh_changed_e,
                p->refresh_unexpected_stale);
        fprintf(f,
                "[mbox-probe] WIRING role=%s ap_obj=%s ap_int_mask=0x%x "
                "exported_lines_connected(IOP_NONEMPTY,IOP_EMPTY,AP_NONEMPTY,"
                "AP_EMPTY)=%d,%d,%d,%d latched=%d,%d,%d,%d iop_obj_int_mask=0x%x"
                "\n",
                mb->role, ap->role, ap->int_mask,
                ap->irqs[APPLE_A7IOP_IRQ_IOP_NONEMPTY] != NULL,
                ap->irqs[APPLE_A7IOP_IRQ_IOP_EMPTY] != NULL,
                ap->irqs[APPLE_A7IOP_IRQ_AP_NONEMPTY] != NULL,
                ap->irqs[APPLE_A7IOP_IRQ_AP_EMPTY] != NULL, ap->iop_nonempty,
                ap->iop_empty, ap->ap_nonempty, ap->ap_empty, mb->int_mask);
        {
            int k, n[4];
            bool found[4], deliv[4];
            MboxProbe *app = mbox_probe_get_locked(ap);

            for (k = 0; k < 4; k++) {
                deliv[k] = mbox_probe_line_deliverable(ap, k, &n[k], &found[k]);
            }
            fprintf(f,
                    "[mbox-probe] AIC role=%s (order IOP_NONEMPTY,IOP_EMPTY,"
                    "AP_NONEMPTY,AP_EMPTY) aic_input=%d,%d,%d,%d wired_to_aic="
                    "%d,%d,%d,%d deliverable_now=%d,%d,%d,%d ever_deliverable="
                    "%d,%d,%d,%d ops_deliverable=%" PRIu64 ",%" PRIu64 ",%"
                    PRIu64 ",%" PRIu64 " stale_ops_wrong_NONEMPTY_deliverable="
                    "%" PRIu64 " stale_ops_wrong_EMPTY_deliverable=%" PRIu64
                    " stale_trans_NONEMPTY_deliv=%" PRIu64
                    " stale_trans_EMPTY_deliv=%" PRIu64
                    " heal_flips_deliverable(ne,e)=%" PRIu64 ",%" PRIu64
                    " | AP int-mask writes set=%" PRIu64 " clr=%" PRIu64
                    " or_ever=0x%x\n",
                    mb->role, n[0], n[1], n[2], n[3], found[0], found[1],
                    found[2], found[3], deliv[0], deliv[1], deliv[2], deliv[3],
                    p->ever_deliv[0], p->ever_deliv[1], p->ever_deliv[2],
                    p->ever_deliv[3], p->ops_deliv[0], p->ops_deliv[1],
                    p->ops_deliv[2], p->ops_deliv[3], p->stale_deliv_ne,
                    p->stale_deliv_e, p->stale_deliv_ne_trans,
                    p->stale_deliv_e_trans, p->heal_deliv_ne, p->heal_deliv_e,
                    app->mask_set_calls, app->mask_clr_calls,
                    app->mask_or_ever);
        }
    }
}

/* caller holds the probe lock */
static void mbox_probe_dump_locked(const char *why)
{
    int i;
    FILE *latest;

    fprintf(stderr, "[mbox-probe] ---- %s t=%" PRId64 "ms events=%" PRIu64
            " probes=%d overflow=%d ----\n", why, mbox_probe_now_ms(),
            mbox_probe_events, mbox_probe_n, mbox_probe_overflow);
    for (i = 0; i < mbox_probe_n; i++) {
        mbox_probe_print_one(stderr, &mbox_probes[i]);
    }
    latest = fopen(MBOX_PROBE_LATEST, "w");
    if (latest) {
        fprintf(latest, "[mbox-probe] ---- %s t=%" PRId64 "ms events=%" PRIu64
                " probes=%d overflow=%d ----\n", why, mbox_probe_now_ms(),
                mbox_probe_events, mbox_probe_n, mbox_probe_overflow);
        for (i = 0; i < mbox_probe_n; i++) {
            mbox_probe_print_one(latest, &mbox_probes[i]);
        }
        fclose(latest);
    }
}

static uint64_t mbox_probe_sum_locked(void)
{
    uint64_t sum = mbox_probe_events;
    int i;

    for (i = 0; i < mbox_probe_n; i++) {
        sum += mbox_probes[i].ap_refreshes + mbox_probes[i].update_calls +
               mbox_probes[i].resets + mbox_probes[i].recv_empty_latch;
    }
    return sum;
}

static void mbox_probe_atexit(void)
{
    G_LOCK(mbox_probe);
    mbox_probe_dump_locked("FINAL (atexit)");
    G_UNLOCK(mbox_probe);
}

static void mbox_probe_tick(void *opaque)
{
    uint64_t sum;

    G_LOCK(mbox_probe);
    sum = mbox_probe_sum_locked();
    if (sum != mbox_probe_last_sum && mbox_probe_dumps < MBOX_PROBE_MAX_DUMPS) {
        mbox_probe_last_sum = sum;
        mbox_probe_dumps++;
        mbox_probe_dump_locked("periodic");
    }
    G_UNLOCK(mbox_probe);
    timer_mod(mbox_probe_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + MBOX_PROBE_TICK_MS);
}

static gpointer mbox_probe_init_fn(gpointer unused)
{
    mbox_probe_t0_ms = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    atexit(mbox_probe_atexit);
    mbox_probe_timer = timer_new_ms(QEMU_CLOCK_REALTIME, mbox_probe_tick, NULL);
    timer_mod(mbox_probe_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + MBOX_PROBE_TICK_MS);
    fprintf(stderr, "[mbox-probe] armed (temporary instrumentation)\n");
    return NULL;
}

static void mbox_probe_init_once(void)
{
    g_once(&mbox_probe_once, mbox_probe_init_fn, NULL);
}

/* caller holds the probe lock; also logs the first time each line is seen
 * deliverable */
static void mbox_probe_note_deliv(MboxProbe *p, AppleA7IOPMailbox *ap, int k,
                                  bool deliv)
{
    static const char *const names[4] = { "IOP_NONEMPTY", "IOP_EMPTY",
                                          "AP_NONEMPTY", "AP_EMPTY" };
    int n;
    bool found;

    if (!deliv || p->ever_deliv[k]) {
        return;
    }
    p->ever_deliv[k] = true;
    if (mbox_probe_lines_aic < MBOX_PROBE_CAP_AIC) {
        mbox_probe_lines_aic++;
        (void)mbox_probe_line_deliverable(ap, k, &n, &found);
        fprintf(stderr,
                "[mbox-probe] AIC-DELIVERABLE-FIRST t=%" PRId64 "ms role=%s "
                "line=%s aic_input=%d cpu=%d\n", mbox_probe_now_ms(),
                p->mb->role, names[k], n, mbox_probe_cpu());
    }
}

/* Expected vs latched exported IOP_* levels for the A2I queue of `iop`. */
static void mbox_probe_a2i_levels(AppleA7IOPMailbox *iop, bool *exp_ne,
                                  bool *exp_e, bool *act_ne, bool *act_e,
                                  bool *ne_unm, bool *e_unm)
{
    AppleA7IOPMailbox *ap = iop->ap_mailbox;
    bool empty = QTAILQ_EMPTY(&iop->inbox);

    *ne_unm = iop_nonempty_is_unmasked(ap->int_mask);
    *e_unm = iop_empty_is_unmasked(ap->int_mask);
    *exp_ne = (*ne_unm && !empty) || iop->underflow;
    *exp_e = *e_unm && empty;
    *act_ne = ap->iop_nonempty;
    *act_e = ap->iop_empty;
}

/* caller holds the probe lock */
static void mbox_probe_close_episode(MboxProbe *p, bool by_refresh)
{
    int64_t dur = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - p->ep_start_ns;

    p->ep_open = false;
    p->ep_count++;
    if (by_refresh) {
        p->ep_by_refresh++;
    } else {
        p->ep_by_coincidence++;
    }
    p->ep_ops_total += p->ep_cur_ops;
    p->ep_ns_total += dur;
    if ((uint64_t)dur > p->ep_ns_max) {
        p->ep_ns_max = dur;
    }
    if (by_refresh ? mbox_probe_lines_episode < MBOX_PROBE_CAP_EPISODE
                   : mbox_probe_lines_coinc < MBOX_PROBE_CAP_COINC) {
        if (by_refresh) {
            mbox_probe_lines_episode++;
        } else {
            mbox_probe_lines_coinc++;
        }
        fprintf(stderr,
                "[mbox-probe] EPISODE-END t=%" PRId64 "ms role=%s by=%s "
                "ops=%" PRIu64 " dur_us=%" PRId64 " cpu=%d\n",
                mbox_probe_now_ms(), p->mb->role,
                by_refresh ? "ap-refresh" : "coincidence", p->ep_cur_ops,
                dur / 1000, mbox_probe_cpu());
    }
}

/* Called at the top of update_irq_status(): registers the mailbox and detects
 * a refresh of the exported (AP-side) object. */
static void mbox_probe_on_update(AppleA7IOPMailbox *s)
{
    MboxProbe *p;

    mbox_probe_init_once();
    G_LOCK(mbox_probe);
    p = mbox_probe_get_locked(s);
    p->update_calls++;
    if (s->ap_mailbox == s && s->iop_mailbox != s) {
        MboxProbe *ip = mbox_probe_get_locked(s->iop_mailbox);
        bool exp_ne, exp_e, act_ne, act_e, ne_unm, e_unm;

        int kk;

        ip->ap_refreshes++;
        for (kk = 0; kk < 4; kk++) {
            bool ff;

            mbox_probe_note_deliv(ip, s, kk,
                                  mbox_probe_line_deliverable(s, kk, NULL, &ff));
        }
        mbox_probe_a2i_levels(s->iop_mailbox, &exp_ne, &exp_e, &act_ne, &act_e,
                              &ne_unm, &e_unm);
        if (ip->reset_pending) {
            /* the refresh that reset itself performs after clearing the
             * latched flags: not a stale-line healing, do not count it */
            ip->reset_pending = false;
            ip->ap_refreshes--;
        } else if (exp_ne != act_ne || exp_e != act_e) {
            bool d_ne, d_e, f1, f2;

            d_ne = mbox_probe_line_deliverable(s, APPLE_A7IOP_IRQ_IOP_NONEMPTY,
                                               NULL, &f1);
            d_e = mbox_probe_line_deliverable(s, APPLE_A7IOP_IRQ_IOP_EMPTY,
                                              NULL, &f2);
            ip->heal_deliv_ne += (exp_ne != act_ne) && d_ne;
            ip->heal_deliv_e += (exp_e != act_e) && d_e;
            ip->ap_refresh_changed_ne += (exp_ne != act_ne);
            ip->ap_refresh_changed_e += (exp_e != act_e);
            if (ip->ep_open) {
                mbox_probe_close_episode(ip, true);
            } else {
                ip->refresh_unexpected_stale++;
                if (mbox_probe_lines_misc < MBOX_PROBE_CAP_MISC) {
                    mbox_probe_lines_misc++;
                    fprintf(stderr,
                            "[mbox-probe] SELFCHECK stale-at-refresh with no "
                            "open episode role=%s exp_ne=%d act_ne=%d exp_e=%d "
                            "act_e=%d\n", s->iop_mailbox->role, exp_ne, act_ne,
                            exp_e, act_e);
                }
            }
        }
    }
    G_UNLOCK(mbox_probe);
}

/* After an operation on the A2I queue of `iop` (the coprocessor-side object),
 * check the exported AP-side lines. caller holds the probe lock. */
static void mbox_probe_check_a2i(MboxProbe *p, AppleA7IOPMailbox *iop,
                                 const char *op, bool trans)
{
    AppleA7IOPMailbox *ap = iop->ap_mailbox;
    bool exp_ne, exp_e, act_ne, act_e, ne_unm, e_unm, stale;
    bool d[4], found, ne_bad, e_bad, odd, interesting;
    int k;

    if (ap == iop) {
        return;
    }
    mbox_probe_a2i_levels(iop, &exp_ne, &exp_e, &act_ne, &act_e, &ne_unm,
                          &e_unm);
    for (k = 0; k < 4; k++) {
        d[k] = mbox_probe_line_deliverable(ap, k, NULL, &found);
        p->ops_deliv[k] += d[k];
        mbox_probe_note_deliv(p, ap, k, d[k]);
    }
    p->a2i_ops++;
    p->a2i_ops_ap_not_refreshed++; /* by construction: send/recv on iop obj
                                      only calls update_irq(iop obj) */
    p->trans_ops += trans;
    p->ops_ne_unmasked += ne_unm;
    p->ops_e_unmasked += e_unm;
    ne_bad = exp_ne != act_ne;
    e_bad = exp_e != act_e;
    stale = ne_bad || e_bad;
    if (stale) {
        p->stale_deliv_ne += ne_bad && d[APPLE_A7IOP_IRQ_IOP_NONEMPTY];
        p->stale_deliv_e += e_bad && d[APPLE_A7IOP_IRQ_IOP_EMPTY];
        p->stale_deliv_ne_trans += ne_bad && trans &&
                                   d[APPLE_A7IOP_IRQ_IOP_NONEMPTY];
        p->stale_deliv_e_trans += e_bad && trans &&
                                  d[APPLE_A7IOP_IRQ_IOP_EMPTY];
        /* "odd": the wire is wrongly HIGH for NONEMPTY / wrongly LOW for EMPTY */
        odd = (act_ne && !exp_ne) || (!act_e && exp_e);
        interesting = odd || (ne_bad && d[APPLE_A7IOP_IRQ_IOP_NONEMPTY]) ||
                      (e_bad && d[APPLE_A7IOP_IRQ_IOP_EMPTY]);
        p->stale_ops++;
        p->stale_trans_ops += trans;
        p->stale_ne_high += (act_ne && !exp_ne);
        p->stale_ne_low += (!act_ne && exp_ne);
        p->stale_e_high += (act_e && !exp_e);
        p->stale_e_low += (!act_e && exp_e);
        if (!p->ep_open) {
            p->ep_open = true;
            p->ep_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            p->ep_cur_ops = 0;
        }
        p->ep_cur_ops++;
        if (interesting ? mbox_probe_lines_stale_odd < MBOX_PROBE_CAP_STALE_ODD
                        : mbox_probe_lines_stale < MBOX_PROBE_CAP_STALE) {
            if (interesting) {
                mbox_probe_lines_stale_odd++;
            } else {
                mbox_probe_lines_stale++;
            }
            fprintf(stderr,
                    "[mbox-probe] STALE%s t=%" PRId64 "ms role=%s op=%s trans=%d "
                    "depth=%u ne(exp=%d act=%d unmasked=%d aic_deliv=%d) "
                    "e(exp=%d act=%d unmasked=%d aic_deliv=%d) ap_mask=0x%x "
                    "cpu=%d\n", interesting ? "-ODD" : "",
                    mbox_probe_now_ms(), iop->role, op, trans, iop->count,
                    exp_ne, act_ne, ne_unm, d[APPLE_A7IOP_IRQ_IOP_NONEMPTY],
                    exp_e, act_e, e_unm, d[APPLE_A7IOP_IRQ_IOP_EMPTY],
                    ap->int_mask, mbox_probe_cpu());
        }
    } else if (p->ep_open) {
        mbox_probe_close_episode(p, false);
    }
}

static void mbox_probe_after_send(AppleA7IOPMailbox *s, bool was_empty)
{
    MboxProbe *p;

    mbox_probe_init_once();
    G_LOCK(mbox_probe);
    mbox_probe_events++;
    p = mbox_probe_get_locked(s);
    p->sent++;
    p->to_nonempty += was_empty;
    if (s->count > p->max_depth) {
        p->max_depth = s->count;
    }
    if (s->iop_mailbox == s) {
        mbox_probe_check_a2i(p, s, "send", was_empty);
    }
    G_UNLOCK(mbox_probe);
}

static void mbox_probe_after_recv(AppleA7IOPMailbox *s)
{
    MboxProbe *p;
    bool now_empty = QTAILQ_EMPTY(&s->inbox);

    mbox_probe_init_once();
    G_LOCK(mbox_probe);
    mbox_probe_events++;
    p = mbox_probe_get_locked(s);
    p->recvd++;
    p->to_empty += now_empty;
    if (s->iop_mailbox == s) {
        mbox_probe_check_a2i(p, s, "recv", now_empty);
    }
    G_UNLOCK(mbox_probe);
}

/* (a) a receive that returned NULL. sticky=false: it latched underflow now. */
static void mbox_probe_recv_null(AppleA7IOPMailbox *s, bool sticky)
{
    MboxProbe *p;

    mbox_probe_init_once();
    G_LOCK(mbox_probe);
    mbox_probe_events++;
    p = mbox_probe_get_locked(s);
    if (sticky) {
        p->recv_sticky_null++;
    } else {
        p->recv_empty_latch++;
        if (p->first_underflow_ms == 0) {
            p->first_underflow_ms = mbox_probe_now_ms() + 1;
        }
    }
    if (!sticky ? mbox_probe_lines_underflow < MBOX_PROBE_CAP_UNDERFLOW :
                  (p->recv_sticky_null <= 10 &&
                   mbox_probe_lines_underflow < MBOX_PROBE_CAP_UNDERFLOW)) {
        mbox_probe_lines_underflow++;
        fprintf(stderr,
                "[mbox-probe] UNDERFLOW t=%" PRId64 "ms role=%s dir=%s %s "
                "sent=%" PRIu64 " recvd=%" PRIu64 " depth=%u cpu=%d\n",
                mbox_probe_now_ms(), s->role, mbox_probe_dir(s),
                sticky ? "sticky-null-return" : "LATCHED", p->sent, p->recvd,
                s->count, mbox_probe_cpu());
    }
    G_UNLOCK(mbox_probe);
}

/* send_ap/send_iop/recv_ap/recv_iop refused because the direction is disabled. */
static void mbox_probe_dir_off(AppleA7IOPMailbox *queue, bool is_send)
{
    MboxProbe *p;

    mbox_probe_init_once();
    G_LOCK(mbox_probe);
    p = mbox_probe_get_locked(queue);
    if (is_send) {
        p->send_dir_off++;
    } else {
        p->recv_dir_off++;
    }
    if (mbox_probe_lines_misc < MBOX_PROBE_CAP_MISC) {
        mbox_probe_lines_misc++;
        fprintf(stderr,
                "[mbox-probe] DIR-OFF t=%" PRId64 "ms role=%s dir=%s %s cpu=%d\n",
                mbox_probe_now_ms(), queue->role, mbox_probe_dir(queue),
                is_send ? "send-dropped" : "recv-refused", mbox_probe_cpu());
    }
    G_UNLOCK(mbox_probe);
}

static void mbox_probe_on_mask(AppleA7IOPMailbox *s, bool is_set, uint32_t value)
{
    MboxProbe *p;

    mbox_probe_init_once();
    G_LOCK(mbox_probe);
    p = mbox_probe_get_locked(s);
    if (is_set) {
        p->mask_set_calls++;
        p->mask_or_ever |= value;
    } else {
        p->mask_clr_calls++;
    }
    if (mbox_probe_lines_misc < MBOX_PROBE_CAP_MISC) {
        mbox_probe_lines_misc++;
        fprintf(stderr,
                "[mbox-probe] INT-MASK t=%" PRId64 "ms role=%s dir=%s %s value=0x%x "
                "mask_before=0x%x cpu=%d\n", mbox_probe_now_ms(), s->role,
                mbox_probe_dir(s), is_set ? "SET(mask)" : "CLR(unmask)", value,
                s->int_mask, mbox_probe_cpu());
    }
    G_UNLOCK(mbox_probe);
}

static void mbox_probe_on_reset(AppleA7IOPMailbox *s)
{
    MboxProbe *p;

    mbox_probe_init_once();
    G_LOCK(mbox_probe);
    p = mbox_probe_get_locked(s);
    p->resets++;
    p->resets_with_underflow += s->underflow;
    if (s->ap_mailbox == s && s->iop_mailbox != s) {
        mbox_probe_get_locked(s->iop_mailbox)->reset_pending = true;
    }
    if (mbox_probe_lines_misc < MBOX_PROBE_CAP_MISC) {
        mbox_probe_lines_misc++;
        fprintf(stderr,
                "[mbox-probe] RESET t=%" PRId64 "ms role=%s dir=%s underflow_was=%d "
                "depth_was=%u\n", mbox_probe_now_ms(), s->role,
                mbox_probe_dir(s), s->underflow, s->count);
    }
    G_UNLOCK(mbox_probe);
}
/* ==== MBOX-PROBE END ==== */

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

    mbox_probe_on_update(s); /* MBOX-PROBE */
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
}

void apple_a7iop_mailbox_update_irq(AppleA7IOPMailbox *s)
{
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
    bool probe_was_empty = QTAILQ_EMPTY(&s->inbox); /* MBOX-PROBE */

    assert_nonnull(msg);

    QEMU_LOCK_GUARD(&s->lock);

    trace_apple_a7iop_mailbox_send(s->role, ldq_le_p(msg->data),
                                   ldq_le_p(msg->data + sizeof(uint64_t)));

    QTAILQ_INSERT_TAIL(&s->inbox, msg, next);
    s->count++;
    apple_a7iop_mailbox_update_irq(s);
    mbox_probe_after_send(s, probe_was_empty); /* MBOX-PROBE */

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
            mbox_probe_dir_off(s->ap_mailbox, true); /* MBOX-PROBE */
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
            mbox_probe_dir_off(s->iop_mailbox, true); /* MBOX-PROBE */
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
        mbox_probe_recv_null(s, true); /* MBOX-PROBE */
        return NULL;
    }

    msg = QTAILQ_FIRST(&s->inbox);
    if (msg == NULL) {
        s->underflow = true;
        mbox_probe_recv_null(s, false); /* MBOX-PROBE */
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
    apple_a7iop_mailbox_update_irq(s);
    mbox_probe_after_recv(s); /* MBOX-PROBE */

    return msg;
}

AppleA7IOPMessage *apple_a7iop_mailbox_recv_iop(AppleA7IOPMailbox *s)
{
    AppleA7IOPMessage *msg;

    if (!s->iop_dir_en) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: %s direction not enabled.\n",
                      __FUNCTION__, s->role);
        mbox_probe_dir_off(s->iop_mailbox, false); /* MBOX-PROBE */
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
        mbox_probe_dir_off(s->ap_mailbox, false); /* MBOX-PROBE */
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

    mbox_probe_on_mask(s, true, value); /* MBOX-PROBE */
    s->int_mask |= value;
    apple_a7iop_mailbox_update_irq(s);
}

void apple_a7iop_mailbox_clear_int_mask(AppleA7IOPMailbox *s, uint32_t value)
{
    QEMU_LOCK_GUARD(&s->lock);

    mbox_probe_on_mask(s, false, value); /* MBOX-PROBE */
    s->int_mask &= ~value;
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

    assert_false(s->iop_mailbox == s->ap_mailbox);

    mbox_probe_on_reset(s); /* MBOX-PROBE */
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
