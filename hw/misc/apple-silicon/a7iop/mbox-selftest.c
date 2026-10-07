/*
 * MBOXDIAG self-test: drive the real A7IOP mailbox core through concrete event
 * sequences and compare every EXPORTED line against the level it should have.
 *
 * Diagnostic only; lives on a throw-away measurement branch.
 *
 *   qemu-system-aarch64 -M none -nodefaults -display none -device mbox-selftest
 *
 * "Pins" are real qemu_irq lines: a handler records the last level written, so
 * what is printed is what a connected interrupt controller would have seen, not
 * the core's internal cache. "Want" is recomputed from the queue contents, the
 * underflow flags and the relevant int_mask with the core's own published rule:
 *
 *   IOP_NONEMPTY = (!masked && A2I queue non-empty) || A2I underflow
 *   IOP_EMPTY    =  !masked && A2I queue empty
 *   AP_NONEMPTY  = (!masked && I2A queue non-empty) || I2A underflow
 *   AP_EMPTY     =  !masked && I2A queue empty
 *
 * A2I is the queue stored in the iop-role mailbox object, I2A the one in the
 * ap-role object. The exported pins belong to the ap-role object (sysbus_pass_irq).
 */

#include "qemu/osdep.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/resettable.h"
#include "system/memory.h"
#include "qapi/error.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/misc/apple-silicon/a7iop/mailbox/core.h"

#define TYPE_MBOX_SELFTEST "mbox-selftest"

typedef struct StCtx {
    const char *name;
    AppleA7IOPVersion ver;
    AppleA7IOP *dev;
    MemoryRegion root;
    AddressSpace as;
    int apin[4], ipin[4];
    qemu_irq airq[4], iirq[4];
    unsigned step;
    unsigned stale_steps;
} StCtx;

static const char *const line_names[4] = { "iop_ne", "iop_e", "ap_ne", "ap_e" };

static void st_apin(void *opaque, int n, int level)
{
    ((StCtx *)opaque)->apin[n] = !!level;
}

static void st_ipin(void *opaque, int n, int level)
{
    ((StCtx *)opaque)->ipin[n] = !!level;
}

static unsigned st_qlen(AppleA7IOPMailbox *q)
{
    unsigned n = 0;
    AppleA7IOPMessage *m;

    QTAILQ_FOREACH (m, &q->inbox, next) {
        n++;
    }
    return n;
}

static void st_want(AppleA7IOPMailbox *obj, int want[4])
{
    AppleA7IOPMailbox *io = obj->iop_mailbox, *ap = obj->ap_mailbox;
    bool qa = st_qlen(io) != 0, qi = st_qlen(ap) != 0;
    uint32_t m = obj->int_mask;

    want[0] = ((!(m & IOP_NONEMPTY) && qa) || io->underflow) ? 1 : 0;
    want[1] = (!(m & IOP_EMPTY) && !qa) ? 1 : 0;
    want[2] = ((!(m & AP_NONEMPTY) && qi) || ap->underflow) ? 1 : 0;
    want[3] = (!(m & AP_EMPTY) && !qi) ? 1 : 0;
}

static void st_diff(char *out, size_t n, const int got[4], const int want[4])
{
    size_t used = 0;

    out[0] = 0;
    for (int i = 0; i < 4; i++) {
        if (got[i] != want[i]) {
            used += snprintf(out + used, n - used, "%s%s%s", used ? "," : "",
                             line_names[i], got[i] ? "=HIGH(should be low)" :
                                                      "=LOW(should be high)");
        }
    }
}

static void st_obs(StCtx *c, const char *what)
{
    AppleA7IOPMailbox *ap = c->dev->ap_mailbox, *io = c->dev->iop_mailbox;
    int aw[4], iw[4];
    char ad[200], id[200];

    st_want(ap, aw);
    st_want(io, iw);
    st_diff(ad, sizeof(ad), c->apin, aw);
    st_diff(id, sizeof(id), c->ipin, iw);
    if (ad[0]) {
        c->stale_steps++;
    }
    fprintf(stderr,
            "MBOXST [%s] %02u %-40s qA2I=%u qI2A=%u ufI=%d ufA=%d maskA=0x%x | "
            "EXPORTED pins=%d%d%d%d want=%d%d%d%d %s | iop-object pins=%d%d%d%d "
            "want=%d%d%d%d %s\n",
            c->name, c->step++, what, st_qlen(io), st_qlen(ap), io->underflow,
            ap->underflow, ap->int_mask, c->apin[0], c->apin[1], c->apin[2],
            c->apin[3], aw[0], aw[1], aw[2], aw[3], ad[0] ? ad : "ok", c->ipin[0],
            c->ipin[1], c->ipin[2], c->ipin[3], iw[0], iw[1], iw[2], iw[3],
            id[0] ? id : "ok");
}

/* Register map per version. */
typedef struct StMap {
    hwaddr iop_blk, ap_blk;
    hwaddr mask_set, mask_clr;
    hwaddr a2i_send, a2i_recv, i2a_send, i2a_recv, a2i_ctrl, i2a_ctrl;
    bool wide;                      /* 16-byte frames via two 8-byte accesses */
} StMap;

static const StMap *st_map(AppleA7IOPVersion v)
{
    static const StMap v2 = { 0xB80, 0x4000, 0x0, 0x4, 0x10, 0x18, 0x30, 0x38,
                              0x8, 0x20, false };
    static const StMap v4 = { 0x4100, 0x8100, 0x0, 0x4, 0x700, 0x710, 0x720,
                              0x730, 0x8, 0xC, true };
    static const StMap v6 = { 0x4100, 0x8100, 0xFFFFFFFF, 0xFFFFFFFF, 0x700,
                              0x710, 0x720, 0x730, 0x10, 0x14, true };

    return v == APPLE_A7IOP_V2 ? &v2 : v == APPLE_A7IOP_V4 ? &v4 : &v6;
}

static void st_w(StCtx *c, hwaddr a, uint64_t v, int bytes)
{
    MemTxResult r;

    if (bytes == 8) {
        address_space_stq_le(&c->as, a, v, MEMTXATTRS_UNSPECIFIED, &r);
    } else {
        address_space_stl_le(&c->as, a, (uint32_t)v, MEMTXATTRS_UNSPECIFIED, &r);
    }
}

static uint64_t st_r(StCtx *c, hwaddr a, int bytes)
{
    MemTxResult r;

    return bytes == 8 ? address_space_ldq_le(&c->as, a, MEMTXATTRS_UNSPECIFIED, &r)
                      : address_space_ldl_le(&c->as, a, MEMTXATTRS_UNSPECIFIED, &r);
}

static void st_send(StCtx *c, hwaddr blk, hwaddr reg, uint64_t tag)
{
    const StMap *m = st_map(c->ver);

    if (m->wide) {
        st_w(c, blk + reg, tag, 8);
        st_w(c, blk + reg + 8, ~tag, 8);
    } else {
        st_w(c, blk + reg, tag, 4);
        st_w(c, blk + reg + 4, ~tag, 4);
    }
}

static uint64_t st_recv(StCtx *c, hwaddr blk, hwaddr reg)
{
    return st_r(c, blk + reg, st_map(c->ver)->wide ? 8 : 4);
}

/* AP posts to the coprocessor (A2I), through the ap-role object's register block. */
static void ap_send_a2i(StCtx *c, uint64_t tag)
{
    st_send(c, st_map(c->ver)->ap_blk, st_map(c->ver)->a2i_send, tag);
}

/* Coprocessor drains A2I through the iop-role object's register block. */
static uint64_t iop_recv_a2i(StCtx *c)
{
    return st_recv(c, st_map(c->ver)->iop_blk, st_map(c->ver)->a2i_recv);
}

/* Coprocessor posts to the AP (I2A), through the iop-role object's block. */
static void iop_send_i2a(StCtx *c, uint64_t tag)
{
    st_send(c, st_map(c->ver)->iop_blk, st_map(c->ver)->i2a_send, tag);
}

/* AP drains I2A through the ap-role object's block. */
static uint64_t ap_recv_i2a(StCtx *c)
{
    return st_recv(c, st_map(c->ver)->ap_blk, st_map(c->ver)->i2a_recv);
}

static void ap_mask_clr(StCtx *c, uint32_t v)
{
    st_w(c, st_map(c->ver)->ap_blk + st_map(c->ver)->mask_clr, v, 4);
}

static void ap_mask_set(StCtx *c, uint32_t v)
{
    st_w(c, st_map(c->ver)->ap_blk + st_map(c->ver)->mask_set, v, 4);
}

static uint64_t ap_ctrl_a2i(StCtx *c)
{
    return st_r(c, st_map(c->ver)->ap_blk + st_map(c->ver)->a2i_ctrl, 4);
}

static AppleA7IOPMessage *st_msg(uint8_t tag)
{
    AppleA7IOPMessage *m = g_new0(AppleA7IOPMessage, 1);

    memset(m->data, tag, sizeof(m->data));
    return m;
}

static StCtx *st_new(const char *name, AppleA7IOPVersion ver, const char *role)
{
    StCtx *c = g_new0(StCtx, 1);
    DeviceState *dev = qdev_new(TYPE_APPLE_A7IOP);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    c->name = g_strdup(name);
    c->ver = ver;
    c->dev = APPLE_A7IOP(dev);
    apple_a7iop_init(c->dev, role, 0x10000, ver, NULL, NULL);
    for (int i = 0; i < APPLE_A7IOP_IRQ_MAX; i++) {
        c->airq[i] = qemu_allocate_irq(st_apin, c, i);
        c->iirq[i] = qemu_allocate_irq(st_ipin, c, i);
        sysbus_connect_irq(sbd, i, c->airq[i]);
        sysbus_connect_irq(SYS_BUS_DEVICE(c->dev->iop_mailbox), i, c->iirq[i]);
    }
    sysbus_realize_and_unref(sbd, &error_fatal);
    memory_region_init(&c->root, NULL, "st-root", 0x100000);
    memory_region_add_subregion(&c->root, 0, sysbus_mmio_get_region(sbd, 0));
    address_space_init(&c->as, &c->root, name);
    /* Reset in the order a system reset uses: ap-role object first (measured). */
    device_cold_reset(DEVICE(c->dev->ap_mailbox));
    device_cold_reset(DEVICE(c->dev->iop_mailbox));
    device_cold_reset(DEVICE(c->dev));
    fprintf(stderr, "MBOXST [%s] ---- version=%s role=%s\n", name,
            ver == APPLE_A7IOP_V2 ? "V2" : ver == APPLE_A7IOP_V4 ? "V4" : "V6", role);
    return c;
}

static void st_done(StCtx *c)
{
    fprintf(stderr, "MBOXST [%s] ==== steps with a stale EXPORTED line: %u of %u\n",
            c->name, c->stale_steps, c->step);
}

/* A2I enqueue and dequeue, then I2A enqueue and dequeue, no mask activity. */
static void scenario_basic(const char *name, AppleA7IOPVersion ver, const char *role)
{
    StCtx *c = st_new(name, ver, role);

    st_obs(c, "after reset");
    ap_send_a2i(c, 0x11);
    st_obs(c, "AP posts A2I (ap block send)");
    (void)iop_recv_a2i(c);
    st_obs(c, "coprocessor drains A2I (iop block recv)");
    iop_send_i2a(c, 0x22);
    st_obs(c, "coprocessor posts I2A (iop block send)");
    (void)ap_recv_i2a(c);
    st_obs(c, "AP drains I2A (ap block recv)");
    st_done(c);
}

/* An unrelated AP-side event lands between the enqueue and the dequeue. */
static void scenario_missed_wake(const char *name, AppleA7IOPVersion ver,
                                 const char *role)
{
    StCtx *c = st_new(name, ver, role);

    st_obs(c, "after reset");
    ap_send_a2i(c, 0x11);
    st_obs(c, "AP posts A2I");
    if (ver == APPLE_A7IOP_V6) {
        iop_send_i2a(c, 0x22);
        st_obs(c, "unrelated I2A post (only AP-side refresh)");
    } else {
        ap_mask_clr(c, 0);
        st_obs(c, "unrelated AP mask write (refreshes AP obj)");
    }
    (void)iop_recv_a2i(c);
    st_obs(c, "coprocessor drains A2I");
    if (ver == APPLE_A7IOP_V6) {
        (void)ap_recv_i2a(c);
        st_obs(c, "AP drains the unrelated I2A (AP-side refresh)");
    } else {
        ap_mask_clr(c, 0);
        st_obs(c, "next AP mask write (refreshes AP obj)");
    }
    st_done(c);
}

/* The coprocessor reads an empty inbox. */
static void scenario_underflow_a2i(const char *name, AppleA7IOPVersion ver,
                                   const char *role)
{
    StCtx *c = st_new(name, ver, role);
    uint64_t v;

    st_obs(c, "after reset");
    v = iop_recv_a2i(c);
    fprintf(stderr, "MBOXST [%s]    (read value 0x%" PRIx64 ")\n", name, v);
    st_obs(c, "coprocessor reads EMPTY A2I");
    ap_send_a2i(c, 0x33);
    st_obs(c, "AP posts A2I afterwards");
    v = iop_recv_a2i(c);
    fprintf(stderr, "MBOXST [%s]    (read value 0x%" PRIx64 ", queue should now be empty)\n",
            name, v);
    st_obs(c, "coprocessor tries to drain it");
    fprintf(stderr, "MBOXST [%s]    (AP view of A2I control word: 0x%" PRIx64 ")\n", name,
            ap_ctrl_a2i(c));
    st_done(c);
}

/* The AP reads an empty outbox. */
static void scenario_underflow_i2a(const char *name, AppleA7IOPVersion ver,
                                   const char *role)
{
    StCtx *c = st_new(name, ver, role);
    uint64_t v;

    st_obs(c, "after reset");
    v = ap_recv_i2a(c);
    fprintf(stderr, "MBOXST [%s]    (read value 0x%" PRIx64 ")\n", name, v);
    st_obs(c, "AP reads EMPTY I2A");
    iop_send_i2a(c, 0x44);
    st_obs(c, "coprocessor posts I2A afterwards");
    v = ap_recv_i2a(c);
    fprintf(stderr, "MBOXST [%s]    (read value 0x%" PRIx64 ", queue should now be empty)\n",
            name, v);
    st_obs(c, "AP tries to drain it");
    st_done(c);
}

/* Model-level API calls, as sep.c, sep-sim.c and rtkit.c make them. */
static void scenario_api(const char *name, AppleA7IOPVersion ver, const char *role)
{
    StCtx *c = st_new(name, ver, role);
    AppleA7IOPMessage *m;

    st_obs(c, "after reset");
    apple_a7iop_send_iop(c->dev, st_msg(0x55));
    st_obs(c, "apple_a7iop_send_iop (sep.c:3757 shape)");
    m = apple_a7iop_recv_iop(c->dev);
    g_free(m);
    st_obs(c, "apple_a7iop_recv_iop (sep-sim.c:1004 shape)");
    apple_a7iop_send_ap(c->dev, st_msg(0x66));
    st_obs(c, "apple_a7iop_send_ap (sep-sim.c:323 shape)");
    m = apple_a7iop_recv_ap(c->dev);
    g_free(m);
    st_obs(c, "apple_a7iop_recv_ap");
    st_done(c);
}

/*
 * An A2I message is pending when the device is reset. A system reset resets the
 * ap-role object first, then the iop-role object (measured with the
 * system_reset probe: RESET-ENTER role=X-ap precedes RESET-ENTER role=X-iop), so
 * this resets the two objects in that order. qemu_devices_reset() itself is not
 * used because it does not reach devices created this early in -M none.
 */
static void scenario_reset_pending(const char *name, AppleA7IOPVersion ver,
                                   const char *role, bool ap_first)
{
    StCtx *c = st_new(name, ver, role);

    st_obs(c, "after reset");
    ap_send_a2i(c, 0x77);
    if (ver == APPLE_A7IOP_V6) {
        st_obs(c, "AP posts A2I (v6 refresh makes pins exact)");
    } else {
        ap_mask_clr(c, 0);
        st_obs(c, "AP posts A2I, then a mask write refreshes pins");
    }
    if (ap_first) {
        device_cold_reset(DEVICE(c->dev->ap_mailbox));
        st_obs(c, "reset ap-role object (pending msg still queued)");
        device_cold_reset(DEVICE(c->dev->iop_mailbox));
        st_obs(c, "reset iop-role object (queue now cleared)");
    } else {
        device_cold_reset(DEVICE(c->dev->iop_mailbox));
        st_obs(c, "reset iop-role object (queue now cleared)");
        device_cold_reset(DEVICE(c->dev->ap_mailbox));
        st_obs(c, "reset ap-role object");
    }
    st_done(c);
}

/* int_mask across a reset: set a mask on the ap-role block, reset both objects. */
static void scenario_mask_reset(const char *name, AppleA7IOPVersion ver, const char *role)
{
    StCtx *c = st_new(name, ver, role);

    st_obs(c, "after reset");
    ap_mask_set(c, IOP_EMPTY | AP_EMPTY);
    st_obs(c, "AP masks IOP_EMPTY and AP_EMPTY");
    device_cold_reset(DEVICE(c->dev->ap_mailbox));
    device_cold_reset(DEVICE(c->dev->iop_mailbox));
    st_obs(c, "reset both objects (is the mask cleared?)");
    st_done(c);
}

static void mbox_selftest_realize(DeviceState *dev, Error **errp)
{
    scenario_basic("V4/SEP basic", APPLE_A7IOP_V4, "SEP");
    scenario_basic("V2/SEP basic", APPLE_A7IOP_V2, "SEP");
    scenario_basic("V4/RTK basic", APPLE_A7IOP_V4, "RTK");
    scenario_mask_reset("V4/SEP mask-reset", APPLE_A7IOP_V4, "SEP");
    scenario_missed_wake("V4/SEP missed-wake", APPLE_A7IOP_V4, "SEP");
    scenario_missed_wake("V2/SEP missed-wake", APPLE_A7IOP_V2, "SEP");
    scenario_underflow_a2i("V4/SEP uf-a2i", APPLE_A7IOP_V4, "SEP");
    scenario_underflow_i2a("V4/SEP uf-i2a", APPLE_A7IOP_V4, "SEP");
    scenario_api("V4/SEP api", APPLE_A7IOP_V4, "SEP");
    scenario_api("V4/RTK api", APPLE_A7IOP_V4, "RTK");
    scenario_basic("V6/SEP basic", APPLE_A7IOP_V6, "SEP");
    scenario_missed_wake("V6/SEP missed-wake", APPLE_A7IOP_V6, "SEP");
    scenario_underflow_a2i("V6/SEP uf-a2i", APPLE_A7IOP_V6, "SEP");
    scenario_underflow_i2a("V6/SEP uf-i2a", APPLE_A7IOP_V6, "SEP");
    scenario_api("V6/SEP api", APPLE_A7IOP_V6, "SEP");
    scenario_reset_pending("V6/SEP reset-pending ap-then-iop", APPLE_A7IOP_V6, "SEP", true);
    scenario_reset_pending("V6/SEP reset-pending iop-then-ap", APPLE_A7IOP_V6, "SEP", false);
    scenario_reset_pending("V4/SEP reset-pending ap-then-iop", APPLE_A7IOP_V4, "SEP", true);
    scenario_reset_pending("V4/SEP reset-pending iop-then-ap", APPLE_A7IOP_V4, "SEP", false);
    fflush(stderr);
    exit(0);
}

static void mbox_selftest_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = mbox_selftest_realize;
    dc->user_creatable = true;
}

static const TypeInfo mbox_selftest_info = {
    .name = TYPE_MBOX_SELFTEST,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(DeviceState),
    .class_init = mbox_selftest_class_init,
};

static void mbox_selftest_register(void)
{
    type_register_static(&mbox_selftest_info);
}

type_init(mbox_selftest_register);
