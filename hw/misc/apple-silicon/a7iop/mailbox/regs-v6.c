/*
 * Apple A7IOP V6 Mailbox Registers (ASC "ascwrap-v6").
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Offsets and semantics are taken from XNU's own AppleA7IOP driver in the
 * pinned iOS 27 boot kernel collection (sha256 a36b9241...26b35), not from a
 * reference implementation:
 *
 *   - The register names are Apple's. The driver formats
 *     "IDLE_STATUS: 0x%08x\nINBOX0_CTRL: 0x%08x\nOUTBOX0_CTRL: 0x%08x\n"
 *     from reads of wrapper +0x8000, +0x8110 and +0x8114.
 *   - "Inbox" is the coprocessor's inbox, i.e. the AP's send direction (A2I).
 *     "Outbox" is the AP's receive direction (I2A). The driver passes the
 *     literals "Inbox" and "Outbox" to its overflow logger after reading
 *     +0x8110 and +0x8114 respectively.
 *   - Bit 0 of a CONTROL word is enable/ready, bit 17 is EMPTY (proven in both
 *     directions by the branch following a ubfx #17,#1), bits 18 and 19 are
 *     overflow/underflow, and bits 23:20 are a four-bit message count.
 *   - Bit 16 has a compiled accessor with no callers anywhere in the
 *     collection, so the Linux name FULL is unverified and is not relied on.
 *
 * The data registers are deliberately identical to the V4 file: with the
 * mailbox mapped at wrapper + 0x8100, V4's REG_IOP_SEND0 already resolves to
 * 0x8800 and REG_AP_RECV0 to 0x8830, which are exactly the two apertures XNU
 * uses. Only the CONTROL pair moved, from +0x8108/+0x810C to +0x8110/+0x8114.
 */

#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "private.h"
#include "trace.h"
#include "hw/core/cpu.h"

/*
 * Block-relative offsets. The mailbox region is mapped at wrapper + 0x8100,
 * so add 0x8100 for the absolute wrapper offsets quoted above.
 */
#define REG_A2I_CTRL (0x10)  /* abs 0x8110, Apple's INBOX0_CTRL  */
#define REG_I2A_CTRL (0x14)  /* abs 0x8114, Apple's OUTBOX0_CTRL */
#define REG_A2I_SEND0 (0x700) /* abs 0x8800 */
#define REG_A2I_SEND1 (0x704)
#define REG_A2I_SEND2 (0x708) /* abs 0x8808, second half of XNU's 16-byte stp */
#define REG_A2I_SEND3 (0x70C)
#define REG_A2I_RECV0 (0x710) /* declared: coprocessor side, never read by AP */
#define REG_A2I_RECV1 (0x714)
#define REG_A2I_RECV2 (0x718)
#define REG_A2I_RECV3 (0x71C)
#define REG_I2A_SEND0 (0x720) /* declared: coprocessor side, never written by AP */
#define REG_I2A_SEND1 (0x724)
#define REG_I2A_SEND2 (0x728)
#define REG_I2A_SEND3 (0x72C)
#define REG_I2A_RECV0 (0x730) /* abs 0x8830 */
#define REG_I2A_RECV1 (0x734)
#define REG_I2A_RECV2 (0x738) /* abs 0x8838, second half of XNU's 16-byte ldp */
#define REG_I2A_RECV3 (0x73C)

/*
 * Two defects in the shared mailbox core are worked around here rather than
 * fixed there, because the legacy t8030 SEP depends on that code and boots.
 *
 * 1. IRQ fan-out is one-way. Updating the AP mailbox also refreshes the IOP
 *    mailbox, but not the reverse. Only the AP mailbox's four lines leave the
 *    device, and two of them (IOP_EMPTY, IOP_NONEMPTY) describe the A2I queue,
 *    which belongs to the IOP mailbox. So A2I traffic left those exported
 *    lines stale. XNU depends on one of them: provider interrupt index 1, our
 *    IOP_EMPTY, is the line its inbox filter uses to wake a sender blocked in
 *    postMailbox once the coprocessor drains the queue. Refresh the AP
 *    mailbox's lines after every A2I enqueue and dequeue.
 *
 * 2. Underflow is sticky. The core latches underflow on a read of an empty
 *    queue and clears it only at reset; afterwards every receive returns NULL
 *    and the NONEMPTY line is forced high, which is a permanent interrupt
 *    storm. XNU checks EMPTY before reading and so should never trigger it, but
 *    one stray read must not wedge the device. An empty read here returns zero
 *    and latches nothing. That is a declared choice: no source says what the
 *    hardware reports, and XNU's own driver treats a reported underflow as
 *    fatal (it latches a flag that permanently disables postMailbox), so
 *    reporting one would break the guest just as surely.
 */
static void apple_a7iop_v6_refresh_lines(AppleA7IOPMailbox *s)
{
    apple_a7iop_mailbox_update_irq(s->ap_mailbox);
}

static void apple_a7iop_v6_mailbox_reg_write(void *opaque, hwaddr addr,
                                             const uint64_t data, unsigned size)
{
    AppleA7IOPMailbox *s = opaque;
    AppleA7IOPMessage *msg;

    s->diagnostic_mmio_writes++;
    trace_apple_a7iop_mailbox_write(s->role, 6, addr, size, data);
    switch (addr) {
    case REG_A2I_CTRL:
        apple_a7iop_mailbox_set_iop_ctrl(s, (uint32_t)data);
        break;
    case REG_I2A_CTRL:
        /*
         * Measured handshake: the driver enables the channel by writing bit 0
         * of OUTBOX0_CTRL and then polls bit 0 of INBOX0_CTRL with a deadline,
         * failing 0xe00002d6 on timeout. Both directions reset enabled, so
         * that poll already succeeds from reset; the mirror below only matters
         * after the driver's stop path has written 0. Treating the channel as
         * one unit there is a declared choice -- no source says whether the
         * hardware disables A2I when OUTBOX0_CTRL is cleared.
         */
        apple_a7iop_mailbox_set_ap_ctrl(s, (uint32_t)data);
        apple_a7iop_mailbox_set_iop_ctrl(s, (uint32_t)data);
        break;
    case REG_A2I_SEND0:
    case REG_A2I_SEND1:
    case REG_A2I_SEND2:
    case REG_A2I_SEND3:
        qemu_mutex_lock(&s->lock);
        memcpy(s->iop_send_reg + (addr - REG_A2I_SEND0), &data, size);
        /*
         * XNU posts with one 16-byte stp, which arrives as two 8-byte writes
         * at +0x800 and +0x808; the second completes the frame.
         */
        if (addr + size - 4 == REG_A2I_SEND3) {
            msg = g_new0(AppleA7IOPMessage, 1);
            memcpy(msg->data, s->iop_send_reg, sizeof(msg->data));
            qemu_mutex_unlock(&s->lock);
            apple_a7iop_mailbox_send_iop(s, msg);
            apple_a7iop_v6_refresh_lines(s);
        } else {
            qemu_mutex_unlock(&s->lock);
        }
        break;
    case REG_I2A_SEND0:
    case REG_I2A_SEND1:
    case REG_I2A_SEND2:
    case REG_I2A_SEND3:
        qemu_mutex_lock(&s->lock);
        memcpy(s->ap_send_reg + (addr - REG_I2A_SEND0), &data, size);
        if (addr + size - 4 == REG_I2A_SEND3) {
            msg = g_new0(AppleA7IOPMessage, 1);
            memcpy(msg->data, s->ap_send_reg, sizeof(msg->data));
            qemu_mutex_unlock(&s->lock);
            apple_a7iop_mailbox_send_ap(s, msg);
        } else {
            qemu_mutex_unlock(&s->lock);
        }
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "%s unknown @ 0x" HWADDR_FMT_plx " value 0x%" PRIx64 "\n",
                      __FUNCTION__, addr, data);
        break;
    }
}

static uint64_t apple_a7iop_v6_mailbox_reg_read(void *opaque, hwaddr addr,
                                                unsigned size)
{
    AppleA7IOPMailbox *s = opaque;
    AppleA7IOPMessage *msg;
    uint64_t ret = 0;

    s->diagnostic_mmio_reads++;
    trace_apple_a7iop_mailbox_read(s->role, 6, addr, size);
    /*
     * Name the kext driving the GFX RTKit mailbox. The wrapper region sees
     * exactly ONE access a boot (CPU_CTRL +0x44, from AppleASCWrapV6 at linked
     * 0xfffffff00856edec); the real HELLO/EPMAP/rollcall traffic rides these
     * mailbox subregions instead. The open question is who sends the EPMAP
     * reply that DECLINES the firmware's own channels (raw 0x21 gfx_msgs and
     * 0x23 gfx_iop_msgs) with an empty bitmap, leaving only crashlog 0x20
     * started. a7iop builds target-agnostic, so use CPUClass::get_pc rather
     * than CPUARMState. GFX only: SMC and DCP together do ~10k accesses.
     */
    /*
     * NB the mailbox roles are "GFX-ap" and "GFX-iop" (the wrapper's is plain
     * "GFX"), so this must be a prefix match -- an exact strcmp never fires.
     */
    if (s->role != NULL && strncmp(s->role, "GFX", 3) == 0 &&
        current_cpu != NULL) {
        CPUClass *cc = CPU_GET_CLASS(current_cpu);

        qemu_log_mask(LOG_UNIMP, "GFX-MBOX[%s] read +0x%05" PRIx64 " size %u "
                      "[guest pc 0x%016" PRIx64 "]\n", s->role, (uint64_t)addr, size,
                      cc->get_pc ? (uint64_t)cc->get_pc(current_cpu) : 0);
    }
    switch (addr) {
    case REG_A2I_CTRL:
        return apple_a7iop_mailbox_get_iop_ctrl(s);
    case REG_I2A_CTRL:
        return apple_a7iop_mailbox_get_ap_ctrl(s);
    case REG_A2I_RECV0:
        WITH_QEMU_LOCK_GUARD(&s->lock)
        {
            msg = QTAILQ_EMPTY(&s->iop_mailbox->inbox) ? NULL :
                  apple_a7iop_mailbox_recv_iop(s);
            if (msg == NULL) {
                memset(s->iop_recv_reg, 0, sizeof(s->iop_recv_reg));
            } else {
                memcpy(s->iop_recv_reg, msg->data, sizeof(s->iop_recv_reg));
                g_free(msg);
            }
        }
        apple_a7iop_v6_refresh_lines(s);
        QEMU_FALLTHROUGH;
    case REG_A2I_RECV1:
    case REG_A2I_RECV2:
    case REG_A2I_RECV3:
        WITH_QEMU_LOCK_GUARD(&s->lock)
        {
            memcpy(&ret, s->iop_recv_reg + (addr - REG_A2I_RECV0), size);
        }
        break;
    case REG_I2A_RECV0:
        WITH_QEMU_LOCK_GUARD(&s->lock)
        {
            msg = QTAILQ_EMPTY(&s->ap_mailbox->inbox) ? NULL :
                  apple_a7iop_mailbox_recv_ap(s);
            if (msg == NULL) {
                memset(s->ap_recv_reg, 0, sizeof(s->ap_recv_reg));
            } else {
                memcpy(s->ap_recv_reg, msg->data, sizeof(s->ap_recv_reg));
                g_free(msg);
            }
        }
        QEMU_FALLTHROUGH;
    case REG_I2A_RECV1:
    case REG_I2A_RECV2:
    case REG_I2A_RECV3:
        WITH_QEMU_LOCK_GUARD(&s->lock)
        {
            memcpy(&ret, s->ap_recv_reg + (addr - REG_I2A_RECV0), size);
        }
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "%s unknown @ 0x" HWADDR_FMT_plx "\n",
                      __FUNCTION__, addr);
        break;
    }

    return ret;
}

static const MemoryRegionOps apple_a7iop_v6_mailbox_reg_ops = {
    .write = apple_a7iop_v6_mailbox_reg_write,
    .read = apple_a7iop_v6_mailbox_reg_read,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.unaligned = false,
};

void apple_a7iop_mailbox_init_mmio_v6(AppleA7IOPMailbox *s, const char *name)
{
    memory_region_init_io(&s->mmio, OBJECT(s), &apple_a7iop_v6_mailbox_reg_ops,
                          s, name, REG_I2A_RECV3 + 4);
}
