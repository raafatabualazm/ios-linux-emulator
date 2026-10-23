/*
 * apple-modern SEP core: real sepOS on a private Apple CPU. Opt-in
 * (sep-core / sep-core-mailbox), default off.
 *
 * Ports the lab-proven SEPROM handoff + peripherals from apple-sep-lab so the
 * real iOS AppleSEPManager / AppleSEPKeyStore on the AP can drive the ASC-v6
 * handshake against live sepOS (not sep-sim).
 *
 * Framing: Corellium-style sepOS-only research on the J410 (A17) image for
 * build 24A437. Synthetic identity. Not a faithful D47 SEP and not a
 * key-unwrapping vehicle for an existing warm keybag.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "qemu/bswap.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/irq.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "system/memory.h"
#include "target/arm/cpu.h"
#include "hw/arm/apple-silicon/modern-sep-core.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/misc/apple-silicon/a7iop/base.h"

#define SEP_MMIO_BASE   0x200000000ULL
#define SEP_MMIO_SIZE   0x100000000ULL
#define SEP_RAM_AT_ZERO (16ULL << 20)
#define SEP_BOOT_ROLE_STORE_IDX 14

/* ---------- catch-all MMIO ---------- */

static uint64_t sep_mmio_read(void *opaque, hwaddr offset, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "modern-sep-core: MMIO read  0x%" PRIx64
                  " size %u -> 0\n", (uint64_t)(SEP_MMIO_BASE + offset), size);
    return 0;
}

static void sep_mmio_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "modern-sep-core: MMIO write 0x%" PRIx64
                  " size %u value 0x%" PRIx64 "\n",
                  (uint64_t)(SEP_MMIO_BASE + offset), size, value);
}

static const MemoryRegionOps sep_mmio_ops = {
    .read = sep_mmio_read,
    .write = sep_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

/* ---------- IRQ helper ---------- */

static void sep_core_update_irq(AppleModernSEPCore *core)
{
    bool raise = core->t_pending || core->trng_pending || core->mbox_pending ||
                 core->mbox_line;
    if (core->sep_irq) {
        qemu_set_irq(core->sep_irq, raise);
    }
}

/* ---------- PMGR (+0x2c000 status mirror) ---------- */

static uint64_t sep_pmgr_read(void *opaque, hwaddr off, unsigned size)
{
    AppleModernSEPCore *core = opaque;
    uint32_t v, out;

    if (off + size > SEP_CORE_PMGR_SIZE || !core->pmgr_regs) {
        return 0;
    }
    v = core->pmgr_regs[off / 4];
    if ((v & ~0x8000000fu) == 0) {
        uint32_t n = v & 0xfu;
        out = (v & 0x80000000u) | (n << 4) | n;
    } else {
        out = v;
    }
    return out;
}

static void sep_pmgr_write(void *opaque, hwaddr off, uint64_t val,
                           unsigned size)
{
    AppleModernSEPCore *core = opaque;

    if (off + size > SEP_CORE_PMGR_SIZE || !core->pmgr_regs) {
        return;
    }
    {
        uint32_t v = (uint32_t)val;
        if ((v & ~0x8000000fu) == 0) {
            uint32_t n = v & 0xfu;
            v = (v & 0x80000000u) | (n << 4) | n;
        }
        core->pmgr_regs[off / 4] = v;
    }
}

static const MemoryRegionOps sep_pmgr_ops = {
    .read = sep_pmgr_read,
    .write = sep_pmgr_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* ---------- TRNG + IRQ 3 ---------- */

static uint64_t sep_trng_read(void *opaque, hwaddr off, unsigned size)
{
    AppleModernSEPCore *core = opaque;

    if (off + size > SEP_CORE_TRNG_SIZE) {
        return 0;
    }
    return core->trng_regs[off / 4];
}

static void sep_trng_write(void *opaque, hwaddr off, uint64_t val,
                           unsigned size)
{
    AppleModernSEPCore *core = opaque;

    if (off + size > SEP_CORE_TRNG_SIZE) {
        return;
    }
    if (off == 0x10) {
        /* W1C status; keep FIFO|DRBG ready. */
        core->trng_regs[off / 4] &= ~(uint32_t)val;
        core->trng_regs[off / 4] |= 0x101u;
        return;
    }
    if (off == 0x14) {
        uint32_t v = (uint32_t)val;
        if (v & 0x8000u) {
            core->trng_regs[off / 4] = v; /* keep go-bit until KIC claim */
            core->trng_pending = true;
            sep_core_update_irq(core);
            error_report("modern-sep-core: TRNG go → KIC 0x%x (IRQ 3)",
                         SEP_CORE_KIC_TRNG_EVT);
        } else {
            core->trng_regs[off / 4] = v & ~0x8000u;
        }
        return;
    }
    core->trng_regs[off / 4] = (uint32_t)val;
}

static const MemoryRegionOps sep_trng_ops = {
    .read = sep_trng_read,
    .write = sep_trng_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* ---------- KEY.FCFG ---------- */

static uint64_t sep_key_fcfg_read(void *opaque, hwaddr off, unsigned size)
{
    AppleModernSEPCore *core = opaque;
    return off == 0 ? core->key_fcfg_8000 : 0;
}

static void sep_key_fcfg_write(void *opaque, hwaddr off, uint64_t val,
                               unsigned size)
{
    AppleModernSEPCore *core = opaque;

    if (off != 0) {
        return;
    }
    if ((uint32_t)val == 0xffffu) {
        core->key_fcfg_8000 = 0x50000u | 0xffffu;
    } else {
        core->key_fcfg_8000 = (uint32_t)val;
    }
}

static const MemoryRegionOps sep_key_fcfg_ops = {
    .read = sep_key_fcfg_read,
    .write = sep_key_fcfg_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* ---------- timer ---------- */

static void sep_timer_arm(AppleModernSEPCore *core)
{
    uint64_t ticks = core->t_count ? core->t_count : 1;
    int64_t ns = muldiv64(ticks, NANOSECONDS_PER_SECOND, SEP_CORE_TIMER_HZ);
    timer_mod(core->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + ns);
}

static void sep_timer_fire(void *opaque)
{
    AppleModernSEPCore *core = opaque;

    if (!(core->t_ctrl & 1)) {
        return;
    }
    core->t_stat |= 1;
    core->t_pending = true;
    core->t_fires++;
    if (core->t_fires <= 8 || !(core->t_fires % 100)) {
        error_report("modern-sep-core: timer fire #%" PRIu64, core->t_fires);
    }
    sep_core_update_irq(core);
}

static uint64_t sep_timer_read(void *opaque, hwaddr off, unsigned size)
{
    AppleModernSEPCore *core = opaque;

    switch (off) {
    case 0x00: return core->t_ctrl;
    case 0x08: return core->t_stat;
    case 0x18: return core->t_count;
    case 0x400:
    case 0x410:
        return SEP_CORE_SENTINEL;
    default:   return 0;
    }
}

static void sep_timer_write(void *opaque, hwaddr off, uint64_t val,
                            unsigned size)
{
    AppleModernSEPCore *core = opaque;

    switch (off) {
    case 0x00:
        core->t_ctrl = (uint32_t)val;
        if (val & 1) {
            sep_timer_arm(core);
        } else if (core->timer) {
            timer_del(core->timer);
        }
        break;
    case 0x08:
        core->t_stat &= ~(uint32_t)val;
        if (!(core->t_stat & 1)) {
            core->t_pending = false;
            sep_core_update_irq(core);
        }
        break;
    case 0x18:
        core->t_count = (uint32_t)val;
        break;
    default:
        break;
    }
}

static const MemoryRegionOps sep_timer_ops = {
    .read = sep_timer_read,
    .write = sep_timer_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* ---------- KIC +0x818 claim (TRNG / timer / mbox) ---------- */

static uint64_t sep_kic_read(void *opaque, hwaddr off, unsigned size)
{
    AppleModernSEPCore *core = opaque;

    if (off == 0x18) { /* absolute +0x818 */
        if (core->trng_pending) {
            core->trng_pending = false;
            core->trng_regs[0x14 / 4] &= ~0x8000u;
            sep_core_update_irq(core);
            error_report("modern-sep-core: KIC claim TRNG 0x%x (IRQ 3)",
                         SEP_CORE_KIC_TRNG_EVT);
            return SEP_CORE_KIC_TRNG_EVT;
        }
        if (core->mbox_pending) {
            core->mbox_pending = false;
            sep_core_update_irq(core);
            error_report("modern-sep-core: KIC claim mbox 0x%x (IRQ 0x80)",
                         SEP_CORE_KIC_MBOX_EVT);
            return SEP_CORE_KIC_MBOX_EVT;
        }
        if (core->mbox_line && core->a7iop && core->a7iop->iop_mailbox) {
            /*
             * Live ASC-v6 (shared with AppleSEPManager): our +0x800 overlay
             * shadows the wrapper's own +0x818, so forward the claim. The
             * a7iop masks the claimed source (e.g. IOP_NONEMPTY) until sepOS
             * clears it via INT_MASK_CLR, as on the lab model.
             */
            AppleA7IOPMailbox *mb = core->a7iop->iop_mailbox;
            uint32_t st = apple_a7iop_mailbox_read_interrupt_status(mb);

            apple_a7iop_mailbox_update_irq(mb);
            if (core->mbox_claims++ < 64) {
                error_report("modern-sep-core: KIC claim a7iop 0x%x", st);
            }
            if (st) {
                return st;
            }
        }
        if (core->t_pending) {
            core->t_pending = false;
            sep_core_update_irq(core);
            return SEP_CORE_KIC_TIMER_EVT;
        }
        return 0;
    }
    return 0;
}

/*
 * SEPROM-equivalent boot descriptor. sepOS sep64 (image 0x7cf8) spins while
 * A2I_CTRL (+0x4110) bit17 EMPTY is set, then pops +0x4810..+0x481c and
 * decodes the handoff region: (base>>12)<<32 | (size>>12)<<16 | 0xfe. On the
 * lab this is the injector's reset message; in apple-modern the A2I FIFO is
 * the live ASC-v6 shared with the AP, so post it there once per reset, right
 * when sepOS programs its KIC (+0x80c), just before the poll.
 * SEP_CORE_BOOTDESC=off disables.
 */
static void sep_core_post_boot_desc(AppleModernSEPCore *core)
{
    AppleA7IOPMessage *msg;
    const char *env = getenv("SEP_CORE_BOOTDESC");

    if (core->boot_desc_sent || !core->a7iop || (env && !strcmp(env, "off"))) {
        return;
    }
    core->boot_desc_sent = true;
    msg = g_new0(AppleA7IOPMessage, 1);
    stl_le_p(msg->data + 0x0, 0x040000feu);
    stl_le_p(msg->data + 0x4, (uint32_t)(SEP_CORE_REGION_BASE >> 12));
    stl_le_p(msg->data + 0x8, 0);
    stl_le_p(msg->data + 0xc, 0);
    apple_a7iop_send_iop(core->a7iop, msg);
    error_report("modern-sep-core: boot descriptor → A2I ep=0xfe "
                 "region=0x%" PRIx64 " (SEPROM-equivalent)",
                 (uint64_t)SEP_CORE_REGION_BASE);
}

static void sep_kic_write(void *opaque, hwaddr off, uint64_t val,
                          unsigned size)
{
    AppleModernSEPCore *core = opaque;

    qemu_log_mask(LOG_UNIMP, "modern-sep-core: KIC write +0x%" HWADDR_PRIx
                  " = 0x%" PRIx64 "\n", off + 0x800, val);
    if (off == 0x0c) {
        sep_core_post_boot_desc(core);
    }
}

static const MemoryRegionOps sep_kic_ops = {
    .read = sep_kic_read,
    .write = sep_kic_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* ---------- optional state watch (SEP_CORE_WATCH=<ms>) ---------- */

static void sep_core_watch_tick(void *opaque)
{
    AppleModernSEPCore *core = opaque;
    CPUARMState *env = &core->cpu->env;
    uint64_t pc = env->pc;
    uint64_t esr = env->cp15.esr_el[1];
    uint64_t elr = env->elr_el[1];

    if (pc != core->watch_last_pc || esr != core->watch_last_esr ||
        elr != core->watch_last_elr) {
        error_report("modern-sep-core: watch pc=0x%" PRIx64 " el=%d "
                     "esr_el1=0x%" PRIx64 " elr_el1=0x%" PRIx64
                     " far_el1=0x%" PRIx64 " vbar_el1=0x%" PRIx64
                     " sp=0x%" PRIx64 " mpidr_aff=0x%" PRIx64,
                     pc, (int)extract32(env->pstate, 2, 2), esr, elr, env->cp15.far_el[1],
                     env->cp15.vbar_el[1], env->xregs[31],
                     core->cpu->mp_affinity);
        core->watch_last_pc = pc;
        core->watch_last_esr = esr;
        core->watch_last_elr = elr;
    }
    timer_mod(core->watch_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
              core->watch_ms);
}

static void sep_core_watch_init(AppleModernSEPCore *core)
{
    const char *env = getenv("SEP_CORE_WATCH");
    uint64_t ms;

    if (!env || !*env || qemu_strtou64(env, NULL, 0, &ms) < 0 || !ms) {
        return;
    }
    core->watch_ms = ms;
    core->watch_last_pc = UINT64_MAX;
    core->watch_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, sep_core_watch_tick,
                                     core);
    timer_mod(core->watch_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + ms);
    error_report("modern-sep-core: SEP_CORE_WATCH every %" PRIu64 " ms "
                 "(diagnostic: logs pc/esr/elr/far on change)", ms);
}

/* ---------- patches / phase2 ---------- */

static void sep_core_apply_patches(AppleModernSEPCore *core)
{
    const char *spec = getenv("SEP_PATCH");
    uint8_t *kram;
    g_auto(GStrv) items = NULL;
    int i;

    if (!spec || !*spec || !core->image_size) {
        return;
    }
    kram = memory_region_get_ram_ptr(&core->kram);
    items = g_strsplit(spec, ",", -1);
    for (i = 0; items[i]; i++) {
        char *eq = strchr(items[i], '=');
        uint64_t va, off, word64;

        if (!eq) {
            continue;
        }
        *eq = '\0';
        if (qemu_strtou64(g_strstrip(items[i]), NULL, 0, &va) < 0 ||
            qemu_strtou64(g_strstrip(eq + 1), NULL, 0, &word64) < 0) {
            error_report("modern-sep-core: SEP_PATCH bad entry '%s'", items[i]);
            continue;
        }
        off = (va >= SEP_CORE_KRAM_BASE) ? (va - SEP_CORE_KRAM_BASE)
                                         : (va & 0xffffffffULL);
        if (off + 4 > core->image_size) {
            error_report("modern-sep-core: SEP_PATCH off 0x%" PRIx64 " OOB",
                         off);
            continue;
        }
        {
            uint32_t word = (uint32_t)word64;
            memcpy(kram + off, &word, 4);
            error_report("modern-sep-core: SEP_PATCH [0x%" PRIx64 "] = 0x%08x",
                         off, word);
        }
    }
}

static void sep_core_apply_phase2(AppleModernSEPCore *core)
{
    uint8_t *kram;
    uint32_t retab = 0xd65f0fffu;
    uint32_t b_tramp;
    uint32_t tramp[6];
    uint32_t bl_imm;
    int32_t off;
    uint64_t fo;
    const char *env = getenv("SEP_CORE_PHASE2");

    /* Default ON with sep-core; set SEP_CORE_PHASE2=off to skip. */
    if (env && !strcmp(env, "off")) {
        return;
    }
    if (!core->image_size) {
        return;
    }
    kram = memory_region_get_ram_ptr(&core->kram);

    fo = SEP_CORE_EP_FO(SEP_CORE_EP_START_EXIT);
    if (fo + 4 > core->image_size) {
        error_report("modern-sep-core: sep-phase2 start-all exit OOB");
        return;
    }
    memcpy(kram + fo, &retab, 4);

    off = (int32_t)SEP_CORE_EP_START_ALL - (int32_t)(SEP_CORE_EP_TRAMP + 12);
    bl_imm = 0x94000000u | (((uint32_t)(off >> 2)) & 0x03ffffffu);
    tramp[0] = 0xa9bf7bfdu;
    tramp[1] = 0x910003fdu;
    tramp[2] = 0xaa1f03e0u;
    tramp[3] = bl_imm;
    tramp[4] = 0xa8c17bfdu;
    tramp[5] = retab;
    fo = SEP_CORE_EP_FO(SEP_CORE_EP_TRAMP);
    if (fo + sizeof(tramp) > core->image_size) {
        error_report("modern-sep-core: sep-phase2 trampoline OOB");
        return;
    }
    memcpy(kram + fo, tramp, sizeof(tramp));

    off = (int32_t)SEP_CORE_EP_TRAMP - (int32_t)SEP_CORE_EP_CREATE_RET;
    b_tramp = 0x14000000u | (((uint32_t)(off >> 2)) & 0x03ffffffu);
    fo = SEP_CORE_EP_FO(SEP_CORE_EP_CREATE_RET);
    if (fo + 4 > core->image_size) {
        error_report("modern-sep-core: sep-phase2 create ret OOB");
        return;
    }
    memcpy(kram + fo, &b_tramp, 4);
    error_report("modern-sep-core: sep-phase2 on (create→start-all; "
                 "AKF IRQ 0x80 path)");
}

/* ---------- SEPROM handoff seed ---------- */

static void sep_core_seed_handoff(AppleModernSEPCore *core)
{
    uint32_t *sram;
    uint32_t *cfg0c40;
    uint32_t *sepmmio;

    if (!core->cpu) {
        return;
    }

    sram = memory_region_get_ram_ptr(&core->sram);
    {
        uint32_t *bpse = (uint32_t *)((uint8_t *)sram +
                                      (SEP_CORE_BPSE_ADDR - SEP_CORE_SRAM_BASE));
        bpse[0] = 0x53455042; /* BPSE */
        bpse[2] = 1;
        bpse[0x70 / 4] = 0x528000;
        /*
         * FMST carve (SEPB+0x78): lab-proven default 0x4000 (apple-sep-lab
         * without sep-stack-fix reaches idle with it). SEP_CORE_FMST=<n>
         * overrides (16K-aligned).
         */
        {
            const char *e = getenv("SEP_CORE_FMST");
            uint64_t carve = 0x4000;

            if (e && *e && qemu_strtou64(e, NULL, 0, &carve) < 0) {
                carve = 0x4000;
            }
            bpse[0x78 / 4] = (uint32_t)carve;
        }
        /* Insecure-RNG seed pair (lab constants, non-secret). */
        bpse[0x80 / 4] = 0x5345504c;
        bpse[0x84 / 4] = 0x00000001;
        bpse[0x88 / 4] = 0x41425321;
        bpse[0x8c / 4] = 0x00000002;
    }

    if (core->pmgr_regs) {
        /* DRAM window [0x1e00000000, 0x1e40000000) — lab-proven. */
        core->pmgr_regs[0x408 / 4] = 0x9001f;
        core->pmgr_regs[0x410 / 4] = 0;
        core->pmgr_regs[0x418 / 4] = 0;
    }

    cfg0c40 = memory_region_get_ram_ptr(&core->cfg0c40);
    cfg0c40[0x180 / 4] = 4;
    cfg0c40[0x1a0 / 4] = 0x4000;

    /* XPRT: MISC + fuse sentinels + UCES. */
    {
        uint8_t *xprt = memory_region_get_ram_ptr(&core->xprt);
        uint32_t *fz = (uint32_t *)(xprt + SEP_CORE_FUSE_OFF);
        unsigned i;

        *(uint32_t *)(xprt + 0x4000) = 0x32b3;
        fz[0] = SEP_CORE_SENTINEL;
        fz[1] = SEP_CORE_SENTINEL;
        fz[2] = SEP_CORE_SENTINEL;
        fz[3] = SEP_CORE_SENTINEL;
        for (i = 0x900 / 4; i <= 0x90c / 4; i++) {
            fz[i] = SEP_CORE_SENTINEL;
        }
        for (i = 0x9b0 / 4; i <= 0x9cc / 4; i++) {
            fz[i] = SEP_CORE_SENTINEL;
        }
        {
            uint32_t *uces = (uint32_t *)(xprt + 0x1c000);
            uces[0x00 / 4] = SEP_CORE_SENTINEL;
            uces[0x08 / 4] = SEP_CORE_SENTINEL;
            uces[0x20 / 4] = SEP_CORE_SENTINEL;
            uces[0x30 / 4] = SEP_CORE_SENTINEL;
        }
    }

    {
        uint32_t *ex = (uint32_t *)memory_region_get_ram_ptr(&core->excl);
        ex[0] = SEP_CORE_SENTINEL;
        ex[2] = SEP_CORE_SENTINEL;
    }
    {
        uint32_t *sab = (uint32_t *)memory_region_get_ram_ptr(&core->akp_sab);
        uint32_t *mmt = (uint32_t *)memory_region_get_ram_ptr(&core->akp_mmt);
        uint32_t *hi = (uint32_t *)memory_region_get_ram_ptr(&core->akp_hi);

        sab[0] = SEP_CORE_SENTINEL;
        sab[2] = SEP_CORE_SENTINEL;
        mmt[0] = SEP_CORE_SENTINEL;
        mmt[2] = SEP_CORE_SENTINEL;
        hi[0] = SEP_CORE_SENTINEL;
        hi[2] = SEP_CORE_SENTINEL;
        hi[(0x2a0bc1800ULL - 0x2a0b00000ULL) / 4] = 0x3;
    }

    memset(core->trng_regs, 0, sizeof(core->trng_regs));
    core->trng_regs[0x00 / 4] = 0x34fbf246u;
    core->trng_regs[0x04 / 4] = 0xb40a6f2du;
    core->trng_regs[0x08 / 4] = 0xc56f4777u;
    core->trng_regs[0x0c / 4] = 0x5f2c2401u;
    core->trng_regs[0x10 / 4] = 0x101u;
    core->trng_regs[0x78 / 4] = 0x00180000u;
    core->trng_regs[0x7c / 4] = 0x02000000u;

    {
        uint32_t *plat = (uint32_t *)memory_region_get_ram_ptr(&core->plat);
        uint32_t *tbase;

        plat[(0x2a0dd8008ULL - SEP_CORE_PLAT_PA) / 4] = SEP_CORE_SENTINEL;
        plat[(0x2a0dc0010ULL - SEP_CORE_PLAT_PA) / 4] = 0x101;
        tbase = &plat[(SEP_CORE_TIMER_PA - SEP_CORE_PLAT_PA) / 4];
        tbase[0x8000 / 4] = 0x40000;
        core->key_fcfg_8000 = 0x40000;
        tbase[0xc000 / 4] = 0x5;
        tbase[0x10008 / 4] = 0x5;
        tbase[0x10010 / 4] = 0x4;
    }

    /*
     * One-shot shmbuf descriptor at ASC +0x4810 (type 0xfe). When the live
     * ASC-v6 alias covers this window, the alias wins (prio 10); the seed
     * remains for pre-attach / soft-reset without mailbox.
     */
    sepmmio = memory_region_get_ram_ptr(&core->sepmmio);
    sepmmio[0x404110 / 4] = 0;
    sepmmio[0x404810 / 4] = 0x040000fe;
    sepmmio[0x404814 / 4] = 0x10000000;
    sepmmio[0x404818 / 4] = 0;
    sepmmio[0x40481c / 4] = 0;

    core->cpu->env.apple_modern_sep_store[SEP_BOOT_ROLE_STORE_IDX] =
        SEP_CORE_BPSE_ADDR | 1ULL;
    core->cpu->env.apple_modern_sep_store[13] = 1ULL;

    /* Region blob: tagged record directory. */
    {
        uint8_t *reg = memory_region_get_ram_ptr(&core->region);
        struct { uint32_t tag; uint32_t count; uint64_t offset; } *rec =
            (void *)reg;
        memset(reg, 0, SEP_CORE_REGION_SIZE);
        rec[0] = (typeof(rec[0])){ 0x43505554, 0x4000, 0x004000 }; /* CPUT */
        rec[1] = (typeof(rec[1])){ 0x434f4e53, 0x4000, 0x008000 }; /* CONS */
        rec[2] = (typeof(rec[2])){ 0x434f5245, 0x4000, 0x00c000 }; /* CORE */
        rec[3] = (typeof(rec[3])){ 0x54524143, 0x4000, 0x010000 }; /* TRAC */
        /*
         * Roottask directory entries (apple-sep-lab Task 8, parser 0xd990):
         * PNIC must be exactly 0x8000 (0xd9cc); FLAG payload lists SEPO
         * bit0 so the TXMB default create at 0xdc30 runs; OPLA/IPIS/TOCS/
         * OTON fill the 4-entry table at 0x174cc (0xfbe8). Without these the
         * roottask asserts and the panic printer recurses into its stack
         * guard (EL0 Perm_L3 at ELR 0xb350 -> obj_tcb.c:173).
         */
        rec[4] = (typeof(rec[4])){ 0x504e4943, 0x8000, 0x014000 }; /* PNIC */
        rec[5] = (typeof(rec[5])){ 0x464c4147, 0x4000, 0x01c000 }; /* FLAG */
        rec[6] = (typeof(rec[6])){ 0x414c504f, 0x4000, 0x020000 };
        rec[7] = (typeof(rec[7])){ 0x53495049, 0x4000, 0x024000 };
        rec[8] = (typeof(rec[8])){ 0x53434f54, 0x4000, 0x028000 };
        rec[9] = (typeof(rec[9])){ 0x4e4f544f, 0x4000, 0x02c000 };
        {
            uint32_t *flag = (uint32_t *)(reg + 0x1c000);

            flag[0] = 1;            /* count */
            flag[1] = 0x5345504f;   /* "SEPO" */
            flag[2] = 1;            /* flags bit0 */
        }
    }

    /* Entry stub X1 = KRAM base (Mach-O copy source). */
    core->cpu->env.xregs[1] = SEP_CORE_KRAM_BASE;
    core->seprom_handoff = true;
}

static void sep_core_reset(void *opaque)
{
    AppleModernSEPCore *core = opaque;

    core->t_pending = false;
    core->trng_pending = false;
    core->mbox_pending = false;
    core->boot_desc_sent = false;
    core->t_ctrl = 0;
    core->t_stat = 0;
    if (core->timer) {
        timer_del(core->timer);
    }
    cpu_reset(CPU(core->cpu));
    cpu_set_pc(CPU(core->cpu), core->entry);
    sep_core_seed_handoff(core);
    sep_core_update_irq(core);
}

bool apple_modern_sep_core_create(Object *owner, AppleModernSEPCore *core,
                                  const char *cpu_type, uint64_t cntfrq,
                                  const char *image_path, Error **errp)
{
    g_autofree char *data = NULL;
    gsize len = 0;
    Object *cpuobj;
    (void)cntfrq;

    if (!image_path || !*image_path) {
        error_setg(errp, "sep-core needs sep-core-image=/path/to/decrypted/sepos");
        return false;
    }
    if (!g_file_get_contents(image_path, &data, &len, NULL)) {
        error_setg(errp, "sep-core: cannot read image '%s'", image_path);
        return false;
    }
    if (len > SEP_CORE_KRAM_SIZE) {
        error_setg(errp, "sep-core: image %zu bytes exceeds SEP KRAM 0x%" PRIx64,
                   (size_t)len, (uint64_t)SEP_CORE_KRAM_SIZE);
        return false;
    }
    core->ram_size = SEP_RAM_AT_ZERO;
    core->entry = SEP_CORE_KRAM_BASE;
    core->image_size = len;

    memory_region_init(&core->container, owner, "modern-sep.space", UINT64_MAX);

    /*
     * Alias the AP system address space at low priority so OOL / shmbuf
     * buffers the AP writes (AppleSEPManager) are reachable at the same PA
     * from the SEP core. Specific SEP private regions overlay at higher prio.
     */
    memory_region_init_alias(&core->ap_alias, owner, "modern-sep.ap-sysmem",
                             get_system_memory(), 0, UINT64_MAX);
    memory_region_add_subregion_overlap(&core->container, 0, &core->ap_alias,
                                        -200);
    core->ap_alias_attached = true;

    memory_region_init_ram(&core->ram, NULL, "modern-sep.ram0", core->ram_size,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0, &core->ram, 0);

    memory_region_init_io(&core->mmio, owner, &sep_mmio_ops, core,
                          "modern-sep.mmio", SEP_MMIO_SIZE);
    memory_region_add_subregion_overlap(&core->container, SEP_MMIO_BASE,
                                        &core->mmio, -100);

    memory_region_init_ram(&core->dram_lo, NULL, "modern-sep.dram-lo",
                           SEP_CORE_DRAM_LO_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_DRAM_LO_BASE,
                                        &core->dram_lo, 0);

    memory_region_init_ram(&core->kram, NULL, "modern-sep.kram",
                           SEP_CORE_KRAM_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_KRAM_BASE,
                                        &core->kram, 0);
    memcpy(memory_region_get_ram_ptr(&core->kram), data, len);

    memory_region_init_ram(&core->sram, NULL, "modern-sep.sram",
                           SEP_CORE_SRAM_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_SRAM_BASE,
                                        &core->sram, 0);

    memory_region_init_ram(&core->carveout, NULL, "modern-sep.carveout",
                           SEP_CORE_CARVEOUT_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_CARVEOUT_BASE,
                                        &core->carveout, 0);

    /* PMGR IO (replaces the old 64 KiB RAM poke page). */
    core->pmgr_regs = g_new0(uint32_t, SEP_CORE_PMGR_SIZE / 4);
    memory_region_init_io(&core->pmgr_mr, NULL, &sep_pmgr_ops, core,
                          "modern-sep.pmgr", SEP_CORE_PMGR_SIZE);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_PMGR_PA,
                                        &core->pmgr_mr, 0);

    memory_region_init_ram(&core->excl, NULL, "modern-sep.excl",
                           SEP_CORE_EXCL_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_EXCL_PA,
                                        &core->excl, 0);

    memory_region_init_ram(&core->akp_sab, NULL, "modern-sep.akp-sab", 0x4000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2a0940000ULL,
                                        &core->akp_sab, 0);
    memory_region_init_ram(&core->akp_mmt, NULL, "modern-sep.akp-mmt", 0x4000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2a0a08000ULL,
                                        &core->akp_mmt, 0);
    memory_region_init_ram(&core->akp_hi, NULL, "modern-sep.akp-hi", 0x140000,
                           &error_fatal);
    memory_region_add_subregion_overlap(&core->container, 0x2a0b00000ULL,
                                        &core->akp_hi, 0);

    memory_region_init_io(&core->trng_mr, NULL, &sep_trng_ops, core,
                          "modern-sep.trng", SEP_CORE_TRNG_SIZE);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_TRNG_PA,
                                        &core->trng_mr, 10);

    memory_region_init_ram(&core->cfg0c40, NULL, "modern-sep.cfg0c40",
                           SEP_CORE_KIC_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_KIC_PA,
                                        &core->cfg0c40, 1);

    memory_region_init_ram(&core->plat, NULL, "modern-sep.plat",
                           SEP_CORE_PLAT_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_PLAT_PA,
                                        &core->plat, 0);

    memory_region_init_io(&core->key_fcfg_mr, NULL, &sep_key_fcfg_ops, core,
                          "modern-sep.key-fcfg", 4);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_KEY_FCFG_PA,
                                        &core->key_fcfg_mr, 10);

    memory_region_init_io(&core->timer_mr, NULL, &sep_timer_ops, core,
                          "modern-sep.timer", 0x1000);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_TIMER_PA,
                                        &core->timer_mr, 20);

    memory_region_init_ram(&core->xprt, NULL, "modern-sep.xprt",
                           SEP_CORE_XPRT_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_XPRT_BASE,
                                        &core->xprt, 0);

    memory_region_init_ram(&core->sepmmio, NULL, "modern-sep.sepmmio",
                           SEP_CORE_SEPMMIO_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_SEPMMIO_BASE,
                                        &core->sepmmio, 0);

    /* KIC claim overlay on ASC +0x800 (wins over sepmmio / mbox alias). */
    memory_region_init_io(&core->kic_mr, NULL, &sep_kic_ops, core,
                          "modern-sep.kic-event", 0x100);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_KIC_EVT_PA,
                                        &core->kic_mr, 20);

    memory_region_init_ram(&core->region, NULL, "modern-sep.region",
                           SEP_CORE_REGION_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_REGION_BASE,
                                        &core->region, 0);

    sep_core_apply_patches(core);
    sep_core_apply_phase2(core);

    address_space_init(&core->as, &core->container, "modern-sep");

    cpuobj = object_new(cpu_type);
    core->cpu = ARM_CPU(cpuobj);
    object_property_add_child(owner, "sep-cpu", cpuobj);
    object_unref(cpuobj);
    object_property_set_bool(cpuobj, "has_el2", false, &error_fatal);
    object_property_set_bool(cpuobj, "has_el3", false, &error_fatal);
    object_property_set_bool(cpuobj, "pauth-noop", false, &error_fatal);
    object_property_set_bool(cpuobj, "apple-modern-sep", true, &error_fatal);
    object_property_set_uint(cpuobj, "cntfrq", SEP_CORE_CNTFRQ, &error_fatal);
    object_property_set_uint(cpuobj, "rvbar", core->entry, &error_fatal);
    /*
     * The SEP is a uniprocessor: sepOS's entry (image 0x4014) takes
     * MPIDR_EL1.Aff0 as its core number and places the boot stack at
     * 0x18000 + 0x4000 * (aff0 + 1). Left to QEMU's default, this CPU gets
     * Aff0 = cpu_index (6 with smp=6), so the stack lands at 0x30000..0x34000
     * inside the page-table pool (0x24000..). The 0x5000 -> 0x8354 page-table
     * build then hands out and zeroes 0x1e40030000, wiping the saved LR; the
     * ret goes to PA 0 (zero RAM), UDF, and the core parks in the sync vector
     * at image+0xa00. Lab (smp=1) has Aff0 = 0. Reproduced in the lab with
     * -global max-arm-cpu.mp-affinity=6 (same SP/X0/X1 at the fault).
     * arm_get_cpu_by_id() still resolves affinity 0 to AP cpu0 first.
     */
    object_property_set_uint(cpuobj, "mp-affinity", 0, &error_fatal);
    object_property_set_link(cpuobj, "memory", OBJECT(&core->container),
                             &error_fatal);
    core->cpu->sme_vq.supported = 0x0b;
    if (!qdev_realize(DEVICE(core->cpu), NULL, errp)) {
        return false;
    }
    core->sep_irq = qdev_get_gpio_in(DEVICE(core->cpu), ARM_CPU_IRQ);
    core->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, sep_timer_fire, core);

    sep_core_seed_handoff(core);
    qemu_register_reset(sep_core_reset, core);
    sep_core_watch_init(core);

    warn_report("apple-modern: sep-core SEPROM+lab peripherals: image '%s' "
                "(%zu B) @PA 0x%" PRIx64 "; PMGR@0x%" PRIx64 "+0x2c000; "
                "TRNG@0x%" PRIx64 "+IRQ3; EXCL@0x%" PRIx64 "; timer@0x%" PRIx64
                "; KIC claim@0x%" PRIx64 "+0x818; AP sysmem aliased for OOL; "
                "phase2=%s; SEP_PATCH env optional (e.g. 0x10350=...). "
                "Synthetic identity; not Apple fidelity",
                image_path, (size_t)len, (uint64_t)SEP_CORE_KRAM_BASE,
                (uint64_t)SEP_CORE_PMGR_PA, (uint64_t)SEP_CORE_TRNG_PA,
                (uint64_t)SEP_CORE_EXCL_PA, (uint64_t)SEP_CORE_TIMER_PA,
                (uint64_t)SEP_CORE_KIC_EVT_PA,
                (getenv("SEP_CORE_PHASE2") &&
                 !strcmp(getenv("SEP_CORE_PHASE2"), "off")) ? "off" : "on");
    return true;
}

static void sep_core_mbox_irq(void *opaque, int n, int level)
{
    AppleModernSEPCore *core = opaque;

    core->mbox_line = level != 0;
    sep_core_update_irq(core);
}

bool apple_modern_sep_core_attach_mailbox(AppleModernSEPCore *core,
                                          AppleA7IOP *a7iop, Error **errp)
{
    if (!core->cpu || !a7iop || !a7iop->iop_mailbox) {
        error_setg(errp, "sep-core-mailbox needs sep-core=on and an ASC-v6 "
                   "SEP wrapper (sep-mailbox=on)");
        return false;
    }
    /* Shared APPLE_A7IOP_V6: AP at 0x282600000, SEP view at 0x2a2400000. */
    memory_region_init_alias(&core->mbox_alias, OBJECT(a7iop),
                             "modern-sep.asc-v6", &a7iop->mmio, 0,
                             memory_region_size(&a7iop->mmio));
    memory_region_add_subregion_overlap(&core->container, SEP_CORE_MBOX_BASE,
                                        &core->mbox_alias, 10);
    /* KIC claim (prio 20) already covers +0x800.. over this alias. */
    core->a7iop = a7iop;
    /* OR the a7iop line with our timer/TRNG sources (one CPU IRQ input). */
    qdev_connect_gpio_out_named(DEVICE(a7iop->iop_mailbox),
                                APPLE_A7IOP_SEP_CPU_IRQ, 0,
                                qemu_allocate_irq(sep_core_mbox_irq, core, 0));
    core->mailbox_attached = true;
    warn_report("apple-modern: sep-core-mailbox: ASC-v6 '%s' shared AP@ADT "
                "reg / SEP@0x%" PRIx64 " (+0x4100 IOP, KIC +0x818→IRQ "
                "0x80/0x83); SEP-iop → ARM_CPU_IRQ; AP OOL via sysmem alias",
                a7iop->role, (uint64_t)SEP_CORE_MBOX_BASE);
    return true;
}
