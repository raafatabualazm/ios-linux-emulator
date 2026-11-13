/*
 * Isolated Apple SEP research machine.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This is NOT a hardware-complete T8140 SEP implementation.  The CPU is
 * QEMU's generic AArch64 model; RAM placement and reset EL are lab choices.
 * Only the AP-facing region metadata below is from D47 / 24A437's device tree.
 * Unknown accesses fail explicitly.  No invented mailbox ACK, keybag, UID,
 * secure-boot result, or crypto completion is generated.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "qemu/timer.h"
#include "hw/boards.h"
#include "hw/irq.h"
#include "hw/qdev-core.h"
#include "hw/loader.h"
#include "migration/blocker.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/reset.h"
#include "system/runstate.h"
#include "system/tcg.h"
#include "target/arm/cpu.h"
#include "target/arm/internals.h"
#include "exec/cputlb.h"
#include "exec/cpu-common.h"
#include "crypto/aes.h"
#include "qom/object.h"

#define TYPE_APPLE_SEP_LAB MACHINE_TYPE_NAME("apple-sep-lab")
OBJECT_DECLARE_SIMPLE_TYPE(AppleSEPLabState, APPLE_SEP_LAB)

/*
 * D47 24A437:
 * arm-io ranges: child 0 -> AP physical 0x210000000.
 * sep reg: 0x72600000/0x88000 and 0x72050000/0x60000.
 * compatible: "iop-sep,ascwrap-v6".
 * Per-register meanings have NOT been recovered.
 */
static const struct {
    hwaddr address;
    uint64_t size;
    const char *name;
} d47_ap_regions[] = {
    { 0x282600000ULL, 0x88000, "ap-region-0" },
    { 0x282050000ULL, 0x60000, "ap-region-1" },
};

typedef struct SEPLabRegion {
    AppleSEPLabState *lab;
    MemoryRegion mr;
    const char *domain;
    const char *name;
    hwaddr base;
} SEPLabRegion;

struct AppleSEPLabState {
    MachineState parent_obj;
    ARMCPU *cpu;
    MemoryRegion private_memory;
    AddressSpace private_as;
    MemoryRegion private_ram;
    MemoryRegion sram;
    SEPLabRegion unknown;
    SEPLabRegion ap[2];
    char *trace_path;
    FILE *trace;
    uint64_t entry;
    uint64_t sequence;
    uint64_t reset_generation;
    uint64_t last_ap_probe;
    bool faulted;
    /*
     * Discovery mode (default off): instead of faulting+stopping on the first
     * unknown MMIO, model the Apple SEP IMPDEF sysregs, back the SEP SRAM, and
     * LOG every unknown access returning 0 so one boot yields the whole ordered
     * MMIO trace. This is a reconnaissance aid, identical in spirit to the M1
     * Unicorn harness (return 0, advance); it fabricates no protocol response.
     * The machine's default (strict, no-fabrication) semantics are unchanged.
     */
    bool discover;
    uint64_t discover_logged;
    /*
     * SEPROM-handoff reconnaissance (default off; implies discover). Backs the
     * SEP RAM carveout and the memory-config register pages with RAM so the
     * exact handoff values (HW regs + "BPSE" boot-args + boot-role pointer) can
     * be poked with gdb and iterated without a rebuild, driving sepOS onto its
     * self-bootstrapping build path. Pure reconnaissance; fabricates nothing.
     */
    bool seprom;
    MemoryRegion carveout;      /* SEP DRAM the kernel allocates page tables in */
    MemoryRegion kram;          /* SEP kernel RAM region at 0x1e40000000 (page tables) */
    qemu_irq sep_irq;           /* the SEP cpu's IRQ input (ARM_CPU_IRQ), host-pulseable */
    MemoryRegion cfg0800;       /* PMGR/cfg window 0x2a0800000 size 0x80000    */
    MemoryRegion cfg0c40;       /* KIC/config 0x2a0c40000 / 0x40000 as RAM      */
    MemoryRegion fuse;          /* SEP security-fuse shadow at 0x2e42c8000      */
    MemoryRegion excl;          /* EXCL sentinel block at 0x2a1000000 (16 KiB)  */
    MemoryRegion akp_sab;       /* AKPESAB 0x2a0940000 / 16 KiB                */
    MemoryRegion akp_mmt;       /* AKP MMT  0x2a0a08000 / 16 KiB                */
    MemoryRegion akp_hi;        /* 0x2a0b00000..0x2a0c40000 (SSEAESAB; gap OK)  */
    MemoryRegion plat;          /* sparse platform pages (dd80/e4xxxx extras)  */
    MemoryRegion sepmmio;       /* broad SEP MMIO swath 0x2a2000000 as pokeable RAM */
    MemoryRegion region;        /* handoff memory region (PA 0x10000000000): the
                                 * tagged record blob SEPROM loads (sep64 0x8f70) */
    MemoryRegion trap;          /* DEBUG: MMIO trap over image page @0x1e40074000 */
    uint8_t trapbuf[0x4000];    /* DEBUG: shadow of that image page              */
    /*
     * SEP-private timer + KIC claim window (default off; property sep-timer=on,
     * requires seprom). Reversed from sepOS j410 24A437:
     *   timer @PA 0x2a0e40000 (kernel VA [0x20b28]):
     *     +0x00 CTRL   0x101 = enable|irq-enable (idle loop 0xd3fc), 0 = stop
     *     +0x08 STAT   W1C; kernel writes 3 to ack (0x10650)
     *     +0x18 COUNT  one-shot reload in 24 MHz ticks (0x249f00 = 100 ms)
     *   KIC @PA 0x2a2400000 (kernel VA [0x20b68]); IRQ entry 0x7150 reads
     *     +0x818 EVENT: [9:0] irq, [18:16] type. type 7 + bit0 set + bit3 clear
     *     dispatches the kernel timer tick 0xd458 (0x7198/0x719c/0x71cc).
     *     Read claims the event (lowers the cpu IRQ). Everything else in the
     *     KIC page stays on the sepmmio RAM swath.
     */
    bool sep_timer;
    MemoryRegion timer_mr;
    MemoryRegion kic_mr;
    uint32_t *pmgr_regs;        /* backing for cfg0800/PMGR window             */
    QEMUTimer *timer;
    uint32_t t_ctrl, t_stat, t_count;
    bool t_pending;
    uint64_t t_fires, t_claims;
    /*
     * sep-inject (default off; needs seprom): lab-side ASC-v6 mailbox player.
     * IOP view at ASC+0x4100 (A2I_CTRL +0x10, A2I_RECV +0x710, I2A_SEND +0x720).
     * Enqueues AP->SEP frames, raises KIC event 0x40000 (IRQ_IOP_NONEMPTY) onto
     * sep_cpu_irq, captures SEP->AP outbox writes. No invented replies.
     */
    bool sep_inject;
    char *inject_script;
    MemoryRegion mbox_mr;
    uint32_t mbox_int_mask;  /* +0x4100 SET / +0x4108 CLR (IOP_NONEMPTY=BIT4) */
    MemoryRegion asc_a00_mr;   /* +0xa00 MASK_SET / +0xa80 MASK_CLR (ext IRQ) */
    MemoryRegion asc_1010_mr;  /* +0x1010/+0x1014 bit1 */
    uint32_t ext_irq_mask;    /* ASC ext IRQ mask; bit3=0x8 gates TRNG IRQ3 */
    uint32_t ext_irq_edge;    /* device-asserted ext IRQs, not yet claimed */
    uint32_t ext_irq_claims;
    bool pmgr28000_latched;   /* +0x28000 rose to 0xf; deliver IRQ 9 once */
    bool pmgr2c000_latched;   /* +0x2c000 rose to 0xf; deliver IRQ 5 once */
    uint32_t a2i_ctrl_en;
    uint32_t i2a_ctrl_en;
    uint8_t a2i_send_scratch[16];
    uint8_t a2i_recv_scratch[16];
    uint8_t i2a_send_scratch[16];
    uint8_t i2a_recv_scratch[16];
    uint8_t a2i_q[16][16];
    unsigned a2i_head, a2i_tail, a2i_count;
    uint8_t outbox_log[64][16];
    unsigned outbox_count;
    bool mbox_pending;
    uint32_t mbox_kic_event; /* default SEP_KIC_MBOX_EVENT; QOM x-inject-kic */
    uint64_t inject_enqueues, inject_dequeues, outbox_posts;
    /*
     * TRNG REGS overlay @ 0x2a0b80000 (EPControl "TRNG", fourcc REGS).
     * App bring-up (0x1197e0) writes 0x63ff to +0x10 as W1C; a later check
     * (0x119d70, cookie 0x120c25) requires bits 0x620c clear. Plain RAM keeps
     * the write and false-panics into IPC 0x7d0 recursion. Overlay implements
     * W1C on +0x10; +0x78/+0x7c carry status seeds.
     */
    MemoryRegion trng_mr;
    uint32_t trng_regs[0x80 / 4];
    bool sep_trng_irq;        /* default off: raise KIC 0x10003 on TRNG complete */
    bool trng_pending;
    MemoryRegion aess_mr;     /* SSEAESAB ('AESS'/'BASE') @ 0x2a0b00000 */
    uint32_t aess_regs[0x80 / 4];
    uint8_t aess_key[32];
    /*
     * sep-phase2 (default off; needs seprom): after EPControl device create
     * (AKF/MBOX irq=-1, TRNG irq=3), run start-all so AKF binds IRQ 0x80 and
     * clears ASC INT_MASK IOP_NONEMPTY. Bridges the missing sks→0x4047 RPC
     * that never fires before idle in the lab.
     */
    bool sep_phase2;
    MemoryRegion key_fcfg_mr;   /* KEY.FCFG +0x8000 @ 0x2a0e48000 (W side-effect) */
    uint32_t key_fcfg_8000;
    /*
     * dxio_async register files. Entitlement phys map names them BASEI2C
     * (0x2a0e80000) and BASEGPIO (0x2a0ec0000), 16 KiB each. Unimplemented
     * reads return 0 and drop writes, so a write of the GPIO command word
     * (+0xc = 0x20c) is invisible to the following poll.
     */
    MemoryRegion i2c_mr;
    MemoryRegion gpio_mr;
    uint32_t *i2c_regs;
    uint32_t *gpio_regs;
    /*
     * sep-stack-fix (default off; needs seprom): fill missing 16K EL0 stack
     * pages (synthetic layout leaves a Trans_L3 hole under SP). Pre-maps on
     * EL0 entry and on EL0 data-abort. Phys pages from top of kram.
     */
    bool stack_fix;
    uint64_t stack_fix_next_pa;
    unsigned stack_fix_fills;
    MemoryRegion dram_lo; /* sep-stack-fix: back memcfg window low slice */
    uint32_t exclog_max;
    uint32_t exclog_n;
    uint64_t exclog_ring[64][16];
    unsigned exclog_ring_pos;
    unsigned exclog_svc_hits;
    uint32_t exclog_svc_mask;
    bool sars_init_notified;
    bool synth_serve;
    bool synth_e0;
    unsigned pmgr2c_count;
    bool xart_e0_send_active;
    bool e0_receive_active;
    uint64_t e0_receive_pc;
    unsigned notify_svc_active;      /* svc 2/3/4 pending on obj_notify */
    uint64_t notify_svc_pc;
    Error *migration_blocker;
};

#define SEP_TIMER_PA   0x2a0e40000ULL
#define SEP_KIC_EVT_PA 0x2a2400800ULL   /* window covers KIC +0x800..+0x8ff */
#define SEP_TIMER_HZ   24000000ULL
#define SEP_KIC_TIMER_EVENT 0x00070001u /* type 7, bit0 valid, bit3 clear */
#define SEP_KIC_MBOX_EVENT  0x00040000u
#define SEP_KIC_TRNG_EVENT  0x00010003u /* type1 id3 → IRQ 3 (sks entropy) */
#define SEP_ASC_MBOX_OFF    0x4100u
#define SEP_ASC_MBOX_SIZE   0x800u
#define SEP_MBOX_CTRL_EN    BIT(0)
#define SEP_MBOX_CTRL_EMPTY BIT(17)
#define SEP_MBOX_CTRL_COUNT_SHIFT 20
#define SEP_MBOX_IOP_NONEMPTY BIT(4) /* a7iop IOP_NONEMPTY; AKF CLR unmasks */
#define SEP_EXT_IRQ_TRNG    BIT(3)   /* ASC +0xa80 unmask value 0x8 */
#define SEP_INJECT_QDEPTH 16
#define SEP_INJECT_OUTLOG 64

static void sep_inject_reset_state(AppleSEPLabState *s);
static void sep_lab_init_inject(AppleSEPLabState *s);
static void sep_lab_init_trng_irq(AppleSEPLabState *s);
static void sep_lab_update_irq(AppleSEPLabState *s);
static void sep_lab_eval_trng_irq(AppleSEPLabState *s);

/* dxio's PMGR +0x28000 on-transition is ext IRQ 9 (mask bit 0x200).
 * SEPD's demux (0x11238c) unmasks that line and calls the slot handler.
 * Re-arming on every unmask while the nibble stays 0xf livelocks the demux.
 * Latch the rising edge and deliver it once. */
#define SEP_EXT_IRQ_PMGR28000 BIT(9)
#define SEP_PMGR_DXIO_OFF     0x28000u

static void sep_lab_raise_pmgr28000(AppleSEPLabState *s)
{
    if (!s->pmgr28000_latched) {
        return;
    }
    if (s->ext_irq_mask & SEP_EXT_IRQ_PMGR28000) {
        return;
    }
    if (s->ext_irq_edge & SEP_EXT_IRQ_PMGR28000) {
        return;
    }
    s->pmgr28000_latched = false;
    s->ext_irq_edge |= SEP_EXT_IRQ_PMGR28000;
    sep_lab_update_irq(s);
}

static void sep_lab_note_pmgr28000(AppleSEPLabState *s, uint32_t old,
                                   uint32_t newv)
{
    bool was = (old & 0xf0u) == 0xf0u;
    bool now = (newv & 0xf0u) == 0xf0u;

    if (now && !was) {
        s->pmgr28000_latched = true;
    } else if (!now) {
        s->pmgr28000_latched = false;
        s->ext_irq_edge &= ~SEP_EXT_IRQ_PMGR28000;
    }
    sep_lab_raise_pmgr28000(s);
}

/* Same one-shot pattern for the bit-5 domain: SEPD's dxio dance writes
 * PMGR +0x8000 then +0x2c000 while ext IRQ 5 (mask bit 0x20) is unmasked
 * and waits for the domain-ready completion. Verified live 2026-10-25:
 * KIC event 0x00010005 claimed at that point stops the retry loop and
 * advances phase 2. +0x2c000 nibble rising to 0xf latches IRQ 5 once. */
#define SEP_EXT_IRQ_PMGR2C000 BIT(5)
/* The +0x2c000 (DXIO2C) power-domain-done waiter in sepOS unmasks ext IRQ
 * bit 7 (0x80) after each +0x2c000 = 0xf write; IRQ 5 alone never completes
 * that wait. Deliver the domain-done on both lines. */
#define SEP_EXT_IRQ_PMGR2C000_IRQ7 BIT(7)
#define SEP_PMGR_DXIO2C_OFF   0x2c000u

static void sep_lab_raise_pmgr2c000(AppleSEPLabState *s)
{
    bool delivered = false;

    if (!s->pmgr2c000_latched) {
        return;
    }
    if (!(s->ext_irq_mask & SEP_EXT_IRQ_PMGR2C000) &&
        !(s->ext_irq_edge & SEP_EXT_IRQ_PMGR2C000)) {
        s->ext_irq_edge |= SEP_EXT_IRQ_PMGR2C000;
        delivered = true;
    }
    if (!(s->ext_irq_mask & SEP_EXT_IRQ_PMGR2C000_IRQ7) &&
        !(s->ext_irq_edge & SEP_EXT_IRQ_PMGR2C000_IRQ7)) {
        s->ext_irq_edge |= SEP_EXT_IRQ_PMGR2C000_IRQ7;
        delivered = true;
    }
    if (delivered) {
        s->pmgr2c000_latched = false;
        sep_lab_update_irq(s);
    }
}

static void sep_lab_note_pmgr2c000(AppleSEPLabState *s, uint32_t old,
                                   uint32_t newv)
{
    bool was = (old & 0xf0u) == 0xf0u;
    bool now = (newv & 0xf0u) == 0xf0u;

    if (now && !was) {
        s->pmgr2c000_latched = true;
    } else if (!now) {
        s->pmgr2c000_latched = false;
        s->ext_irq_edge &= ~(SEP_EXT_IRQ_PMGR2C000 |
                             SEP_EXT_IRQ_PMGR2C000_IRQ7);
    }
    sep_lab_raise_pmgr2c000(s);
}
/*
 * First-app PMGR window (j410 app @file 0x74000; device table name SSEASMBT).
 * VA→PA 0x2a0800000 size 0x80000. Kick +0x2c000=0xf, +0x2c008=0x800000.
 * Poll (app 0x7d3f0): write V (±bit31), wait ubfx(read,4,4)==(V&0xf).
 * Mode writes (only nibble ± bit31) echo status in [7:4]; handoff words
 * like cfg[+0x408]=0x9001f read back raw. Gated with seprom=on (default off).
 */
#define SEP_PMGR_PA     0x2a0800000ULL
#define SEP_PMGR_SIZE   0x80000ULL
/* EXCL (AKPLCXE / FourCC 0x4558434c): sender=3 checks +0 and +8 == 0xa55ac33c
 * (app 0x8db50..0x8db88). 16 KiB window; NOT the ASC mailbox. */
#define SEP_EXCL_PA     0x2a1000000ULL
#define SEP_EXCL_SIZE   0x4000ULL
#define SEP_SENTINEL    0xa55ac33cu
/* Platform block 0x2a2400000/0x6c000: boot descriptor (+0x4110/4810) and
 * timer-event claim at +0x818. Loader also lists KIC at 0x2a0c40000/0x40000. */
#define SEP_ASC_PA      0x2a2400000ULL
#define SEP_KIC_PA      0x2a0c40000ULL
#define SEP_KIC_SIZE    0x40000ULL
#define SEP_AESS_PA     0x2a0b00000ULL
#define SEP_AESS_SIZE   0x80ULL
#define SEP_TRNG_PA     0x2a0b80000ULL
#define SEP_TRNG_SIZE   0x80ULL
#define SEP_KEY_FCFG_PA 0x2a0e48000ULL
#define SEP_I2C_PA      0x2a0e80000ULL  /* BASEI2C, entitlement phys map */
#define SEP_GPIO_PA     0x2a0ec0000ULL  /* BASEGPIO */
#define SEP_IO_BLK_SIZE 0x4000ULL

static uint64_t sep_pmgr_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;
    uint32_t v, out;
    static uint32_t pmgr_rlog;

    if (off + size > SEP_PMGR_SIZE) {
        return 0;
    }
    v = s->pmgr_regs[off / 4];
    /* Mode/power regs: status nibble [7:4] mirrors request [3:0]. Preserve
     * bit31 if set. Do not touch full words like memcfg 0x9001f. */
    if ((v & ~0x8000000fu) == 0) {
        uint32_t n = v & 0xfu;
        out = (v & 0x80000000u) | (n << 4) | n;
    } else {
        out = v;
    }
    if (pmgr_rlog < 2048 && (off == 0x2c000 || off == 0x2c004 ||
                              off == 0x2c008 || off == 0x2c00c ||
                              off == 0x28000 || off == 0x28004 ||
                              off == 0x28008 || off == 0x2800c ||
                              off == 0x8000 || off == 0x40010 ||
                              off == 0x14000 || off == 0x14004 ||
                              off == 0x14008 || off == 0x1400c)) {
        pmgr_rlog++;
        error_report("SEP pmgr: read +0x%" HWADDR_PRIx " raw=0x%x -> 0x%x",
                     off, v, out);
    }
    return out;
}

static bool sep_lab_el1_read_u64(AppleSEPLabState *s, uint64_t va,
                                 uint64_t *value);
static int sep_lab_kernel_rw(AppleSEPLabState *s, uint64_t va, void *buf,
                             int len, bool is_write);
static void sep_lab_dump_tcbmap(AppleSEPLabState *s);

static void sep_pmgr_write(void *opaque, hwaddr off, uint64_t val,
                           unsigned size)
{
    AppleSEPLabState *s = opaque;
    static uint32_t pmgr_log_left = 256;
    static uint32_t pmgr_2c000_count;

    if (off + size > SEP_PMGR_SIZE) {
        return;
    }
    {
        uint32_t old = s->pmgr_regs[off / 4];
        uint32_t v = (uint32_t)val;
        if ((v & ~0x8000000fu) == 0) {
            uint32_t n = v & 0xfu;
            v = (v & 0x80000000u) | (n << 4) | (n);
        }
        s->pmgr_regs[off / 4] = v;
        if (off == SEP_PMGR_DXIO_OFF) {
            sep_lab_note_pmgr28000(s, old, v);
        }
        if (off == SEP_PMGR_DXIO2C_OFF) {
            sep_lab_note_pmgr2c000(s, old, v);
            pmgr_2c000_count++;
            s->pmgr2c_count = pmgr_2c000_count;
            /* Identify the thread that runs the +0x2c000 power-poll loop. */
            if (pmgr_2c000_count == 50 || pmgr_2c000_count == 110) {
                uint64_t cur = 0, pc = 0, wait = 0, parked = 0, name = 0;

                if (sep_lab_el1_read_u64(s, 0xffffffff00020be0ULL, &cur) &&
                    cur) {
                    sep_lab_el1_read_u64(s, cur + 0xf8, &pc);
                    sep_lab_el1_read_u64(s, cur + 0x410, &wait);
                    sep_lab_el1_read_u64(s, cur + 0x3f8, &parked);
                    if (parked) {
                        sep_lab_el1_read_u64(s, parked + 0x10, &name);
                    }
                }
                error_report("SEP pmgr: 2c000 #%u current=0x%" PRIx64
                             " pc=0x%" PRIx64 " wait=0x%" PRIx64
                             " parked=0x%" PRIx64 " name=0x%08" PRIx32,
                             pmgr_2c000_count, cur, pc, wait, parked,
                             (uint32_t)name);
                {
                    /* P1: SEPD registry count (global chain 0x121e78 ->
                     * ptr -> state+0xf58, byte). */
                    uint64_t g = 0, st = 0;
                    uint8_t cnt_direct = 0, cnt_ptr = 0;

                    sep_lab_el1_read_u64(s, 0x4d2489e78ULL, &g);
                    if (g) {
                        sep_lab_kernel_rw(s, g + 0xf58, &cnt_direct, 1,
                                          false);
                        if (sep_lab_el1_read_u64(s, g, &st) && st) {
                            sep_lab_kernel_rw(s, st + 0xf58, &cnt_ptr, 1,
                                              false);
                        }
                    }
                    error_report("SEP p1: reg global=0x%" PRIx64
                                 " state=0x%" PRIx64 " cnt_direct=0x%x"
                                 " cnt_ptr=0x%x", g, st, cnt_direct,
                                 cnt_ptr);
                }
                sep_lab_dump_tcbmap(s);
            }
        }
    }
    if (pmgr_log_left && (off >= 0x10000 || (off & ~0xfffull) == 0x8000)) {
        pmgr_log_left--;
        error_report("SEP pmgr: write +0x%" HWADDR_PRIx " = 0x%" PRIx64
                     " pc=0x%" PRIx64,
                     off, val, (uint64_t)s->cpu->env.pc);
    }
}

static const MemoryRegionOps sep_pmgr_ops = {
    .read = sep_pmgr_read,
    .write = sep_pmgr_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};


static uint64_t sep_trng_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;

    if (off + size > SEP_TRNG_SIZE) {
        return 0;
    }
    if (off < 0x10) {
        /*
         * SEPD 0x11a550 self-test modes (TRNG +0x70):
         *   bit 6 (0x40, Case 0 @ 0x11aa70): AES-conditioning test;
         *     0x11ae00..0x11aef4 unpacks +0x00..+0x0c big-endian against
         *     libShared 0x7f7ed.
         *   bit 7 (0x80, Case 1 @ 0x11a590): DRBG test;
         *     0x11af38..0x11b030 unpacks +0x00..+0x0c big-endian against
         *     libShared 0x7f920.
         */
        static const uint32_t aes_kat[4] = {
            0x46f2fb34u, 0x2d6f0ab4u, 0x77476fc5u, 0x01242c5fu,
        };
        static const uint32_t drbg_kat[4] = {
            0xf640242du, 0xdd34e9e1u, 0x31e71303u, 0x7b1834b7u,
        };
        uint32_t mode = s->trng_regs[0x70 / 4] & 0xc0u;
        if (mode == 0x40u) {
            return aes_kat[off / 4];
        }
        if (mode == 0x80u) {
            return drbg_kat[off / 4];
        }
    }
    return s->trng_regs[off / 4];
}

#define SEP_TRNG_CTRL_IRQ_EN BIT(21) /* TRNG.CTRL 0x0021760f vs 0x0000760f */

static void sep_lab_eval_trng_irq(AppleSEPLabState *s)
{
    if (!s->sep_trng_irq) {
        return;
    }
    if ((s->trng_regs[0x14 / 4] & SEP_TRNG_CTRL_IRQ_EN) &&
        !(s->ext_irq_mask & SEP_EXT_IRQ_TRNG)) {
        if (!s->trng_pending) {
            s->trng_pending = true;
            sep_lab_update_irq(s);
            error_report("SEP TRNG: IRQ 3 pending → KIC 0x%x (CTRL=0x%x)",
                         SEP_KIC_TRNG_EVENT, s->trng_regs[0x14 / 4]);
        }
    } else if (s->trng_pending) {
        s->trng_pending = false;
        sep_lab_update_irq(s);
    }
}

static void sep_trng_write(void *opaque, hwaddr off, uint64_t val,
                           unsigned size)
{
    AppleSEPLabState *s = opaque;

    if (off + size > SEP_TRNG_SIZE) {
        return;
    }
    if (off < 0x10) {
        /* Input block writes at +0x00..+0x0c do not clobber FIFO output. */
        return;
    }
    if (off == 0x10) {
        /*
         * EPControl TRNG status (app 0x1197e0 / 0x119d68..0x119d80):
         * write-1-to-clear. Peer (Antigravity) keeps 0x101 = FIFO ready
         * | DRBG ready across W1C; bit0 alone also satisfies the poll.
         */
        s->trng_regs[off / 4] &= ~(uint32_t)val;
        s->trng_regs[off / 4] |= 0x101u;
        return;
    }
    if (off == 0x14) {
        /*
         * TRNG.CTRL: bit 15 (0x8000) is a synchronous self-clearing command
         * bit polled at EL0 (0x11a24c: tbnz w0, #15); bit 21 (0x200000,
         * 0x0021760f vs 0x0000760f) enables IRQ-driven FIFO refills on IRQ 3
         * (KIC 0x10003), gated by ASC ext-IRQ mask bit 3 (+0xa00/+0xa80).
         */
        uint32_t v = (uint32_t)val & ~0x8000u;
        s->trng_regs[off / 4] = v;
        sep_lab_eval_trng_irq(s);
        return;
    }
    s->trng_regs[off / 4] = (uint32_t)val;
}

static const MemoryRegionOps sep_trng_ops = {
    .read = sep_trng_read,
    .write = sep_trng_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/*
 * SSEAESAB ('AESS'/'BASE' @ PA 0x2a0b00000, size 0x80):
 *   +0x00/+0x08 reset sentinels (0xa55ac33c)
 *   +0x04 STATUS/GO (bit0 go, bit1 busy=0, bits[11:9] err=0)
 *   +0x08 CMD:
 *     low byte 0x0b: latch 128/192/256-bit software key from +0x40..+0x5f
 *     low byte 0x89 (bits[9:8]=0/1/2 for 128/192/256):
 *       AES_Encrypt(Key, P(+0x50..+0x5f) ^ IV(+0x40..+0x4f)) -> +0x70..+0x7f
 *     low byte 0x8a (bits[9:8]=0/1/2 for 128/192/256):
 *       AES_Decrypt(Key, C(+0x40..+0x4f)) ^ IV(+0x50..+0x5f) -> +0x70..+0x7f
 */
static void sep_aess_exec(uint32_t *regs, uint8_t *key)
{
    uint32_t cmd = regs[0x08 / 4];
    uint32_t op = cmd & 0xffu;
    unsigned key_bits = 128u + (((cmd >> 8) & 3u) * 64u);
    uint8_t *in_lo = (uint8_t *)&regs[0x40 / 4];
    uint8_t *in_hi = (uint8_t *)&regs[0x50 / 4];
    uint8_t *out_lo = (uint8_t *)&regs[0x60 / 4];
    uint8_t *out_hi = (uint8_t *)&regs[0x70 / 4];
    uint8_t blk[16];
    AES_KEY aes;
    unsigned i;

    if (key_bits > 256u) {
        key_bits = 128u;
    }
    if (op == 0x0bu) {
        memcpy(key, in_lo, 32);
        return;
    }
    if (op == 0x89u) {
        for (i = 0; i < 16; i++) {
            blk[i] = in_hi[i] ^ in_lo[i];
        }
        AES_set_encrypt_key(key, key_bits, &aes);
        AES_encrypt(blk, out_hi, &aes);
        return;
    }
    if (op == 0x8au) {
        AES_set_decrypt_key(key, key_bits, &aes);
        AES_decrypt(in_lo, blk, &aes);
        for (i = 0; i < 16; i++) {
            out_hi[i] = blk[i] ^ in_hi[i];
        }
        return;
    }
    for (i = 0; i < 16; i++) {
        blk[i] = in_lo[i] ^ in_hi[i] ^ (uint8_t)(cmd + i * 0x11u + 0x5au);
    }
    AES_set_encrypt_key(key, 128, &aes);
    AES_encrypt(blk, out_hi, &aes);
    memcpy(out_lo, out_hi, 16);
    if (op != 0x46u && op != 0x47u) {
        memcpy(key, out_hi, 16);
        memcpy(key + 16, out_hi, 16);
    }
}

static uint64_t sep_aess_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;

    if (off + size > SEP_AESS_SIZE) {
        return 0;
    }
    return s->aess_regs[off / 4];
}

static void sep_aess_write(void *opaque, hwaddr off, uint64_t val,
                           unsigned size)
{
    AppleSEPLabState *s = opaque;

    if (off + size > SEP_AESS_SIZE) {
        return;
    }
    if (off == 0x04) {
        s->aess_regs[0x04 / 4] = (uint32_t)val & ~0xe02u;
        if (val & 1) {
            sep_aess_exec(s->aess_regs, s->aess_key);
        }
        return;
    }
    s->aess_regs[off / 4] = (uint32_t)val;
}

static const MemoryRegionOps sep_aess_ops = {
    .read = sep_aess_read,
    .write = sep_aess_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/*
 * KEY.FCFG +0x8000 (PA 0x2a0e48000): RPC 0x44ca writes 0xffff and checks
 * state[18:16]==5 (peer Antigravity). Seed 0x40000; on 0xffff -> 0x5ffff.
 */
static uint64_t sep_key_fcfg_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;

    (void)size;
    error_report("SEP key_fcfg: read +0x%" HWADDR_PRIx " -> 0x%x pc=0x%" PRIx64,
                 off, off == 0 ? s->key_fcfg_8000 : 0,
                 (uint64_t)s->cpu->env.pc);
    return off == 0 ? s->key_fcfg_8000 : 0;
}

static void sep_key_fcfg_write(void *opaque, hwaddr off, uint64_t val,
                               unsigned size)
{
    AppleSEPLabState *s = opaque;

    (void)size;
    if (off != 0) {
        return;
    }
    if ((uint32_t)val == 0xffffu) {
        s->key_fcfg_8000 = 0x50000u | 0xffffu;
    } else {
        s->key_fcfg_8000 = (uint32_t)val;
    }
    error_report("SEP key_fcfg: write +0x%" HWADDR_PRIx " = 0x%" PRIx64
                 " -> 0x%x pc=0x%" PRIx64,
                 off, val, s->key_fcfg_8000, (uint64_t)s->cpu->env.pc);
}

static uint64_t sep_io_blk_read(void *opaque, hwaddr off, unsigned size)
{
    uint32_t *regs = opaque;

    if (off + 4 > SEP_IO_BLK_SIZE || size != 4) {
        return 0;
    }
    return regs[off / 4];
}

static void sep_io_blk_write(void *opaque, hwaddr off, uint64_t val,
                             unsigned size)
{
    uint32_t *regs = opaque;

    if (off + 4 > SEP_IO_BLK_SIZE || size != 4) {
        return;
    }
    regs[off / 4] = (uint32_t)val;
}

static const MemoryRegionOps sep_io_blk_ops = {
    .read = sep_io_blk_read,
    .write = sep_io_blk_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static const MemoryRegionOps sep_key_fcfg_ops = {
    .read = sep_key_fcfg_read,
    .write = sep_key_fcfg_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void sep_lab_init_timer(AppleSEPLabState *s);
static void sep_lab_init_stack_fix(AppleSEPLabState *s);

/* SEP DRAM carveout for seprom mode (point the memory-config regs here). */
#define SEP_CARVEOUT_BASE 0x2a4000000ULL
/* SEP kernel RAM region: sepOS's build path allocates its page tables here
 * (desc->base 0x1e40024000, from a base hardcoded in the image at 0x6b10,
 * discovered live). MMU is off during the build, so these are physical. */
#define SEP_KRAM_BASE 0x1e40000000ULL
#define SEP_KRAM_SIZE 0x10000000ULL  /* 256 MiB */
/* Memcfg 0x9001f advertises [0x1e00000000, 0x1e40000000). Only kram was
 * backed; sep-stack-fix backs a low slice so FMST/untyped frames are real. */
#define SEP_DRAM_LO_BASE 0x1e00000000ULL
#define SEP_DRAM_LO_SIZE 0x4000000ULL  /* 64 MiB */
#define SEP_CARVEOUT_SIZE 0x10000000ULL  /* 256 MiB */

/* SEP SRAM (stack/data) discovered at boot: SP := 0x2a0220000 (image pc 0x404c).
 * Kept well below the first SEP MMIO block (0x2a0800000) so it shadows none. */
/* Handoff region the 0x2a2404810 encode advertises (base 0x10000000000, size
 * 0x400000 after the sep64 decode). SEPROM backs it with SEP DRAM and writes a
 * tagged record directory (CONS/CORE/CPUT/TRAC/null) into it (sep64 parser at
 * image 0x8f70). Back it as RAM so the loader can lay that blob down and the
 * kernel's object walk reads real records instead of zeros. */
#define SEP_REGION_BASE 0x10000000000ULL
#define SEP_REGION_SIZE 0x1000000ULL  /* 16 MiB >= decoded 0x400000 */
#define SEP_SRAM_BASE 0x2a0200000ULL
#define SEP_SRAM_SIZE 0x400000ULL   /* 4 MiB */
#define SEP_DISCOVER_LOG_CAP 200000

static void sep_lab_trace_reset(AppleSEPLabState *s)
{
    fprintf(s->trace,
            "{\"event\":\"reset\",\"sequence\":%" PRIu64
            ",\"generation\":%" PRIu64 ",\"entry\":\"0x%" PRIx64
            "\",\"profile\":\"t8140-d47-24A437-metadata-only\","
            "\"cpu_model\":\"generic-aarch64\",\"reset_el\":1}\n",
            ++s->sequence, s->reset_generation, s->entry);
    fflush(s->trace);
}

/* Discovery mode: record one JSONL line per unknown access and continue
 * (read returns 0). Capped so a polling loop cannot grow the trace unbounded. */
static MemTxResult sep_lab_discover(SEPLabRegion *r, hwaddr addr,
                                    unsigned size, bool write, uint64_t val)
{
    AppleSEPLabState *s = r->lab;

    if (s->discover_logged < SEP_DISCOVER_LOG_CAP) {
        s->discover_logged++;
        fprintf(s->trace,
                "{\"event\":\"mmio\",\"sequence\":%" PRIu64
                ",\"domain\":\"%s\",\"address\":\"0x%" HWADDR_PRIx
                "\",\"size\":%u,\"write\":%s,\"value\":\"0x%" PRIx64
                "\",\"pc\":\"0x%" PRIx64 "\"}\n",
                ++s->sequence, r->domain, r->base + addr, size,
                write ? "true" : "false", write ? val : 0,
                (uint64_t)s->cpu->env.pc);
        if ((s->discover_logged & 0x3ff) == 0) {
            fflush(s->trace);
        }
        {
            hwaddr abs = r->base + addr;
            if (abs >= SEP_EXCL_PA && abs < SEP_EXCL_PA + SEP_EXCL_SIZE) {
                error_report("SEP excl: %s +0x%" HWADDR_PRIx
                             " size %u (should be RAM-seeded)",
                             write ? "W" : "R", abs - SEP_EXCL_PA, size);
            } else if (abs >= SEP_ASC_PA && abs < SEP_ASC_PA + 0x6c000ULL) {
                static uint32_t asc_log_left = 48;
                if (asc_log_left) {
                    asc_log_left--;
                    error_report("SEP asc: %s +0x%" HWADDR_PRIx
                                 " size %u val=0x%" PRIx64 " pc=0x%" PRIx64,
                                 write ? "W" : "R", abs - SEP_ASC_PA, size,
                                 write ? val : 0, (uint64_t)s->cpu->env.pc);
                }
            }
        }
    }
    return MEMTX_OK;
}

static MemTxResult sep_lab_fault(SEPLabRegion *r, hwaddr addr,
                                unsigned size, bool write)
{
    AppleSEPLabState *s = r->lab;

    /* Avoid a fault storm while the asynchronous stop request is serviced. */
    if (!s->faulted) {
        s->faulted = true;
        fprintf(s->trace,
                "{\"event\":\"unsupported-mmio\",\"sequence\":%" PRIu64
                ",\"generation\":%" PRIu64 ",\"domain\":\"%s\","
                "\"region\":\"%s\",\"address\":\"0x%" HWADDR_PRIx
                "\",\"offset\":\"0x%" HWADDR_PRIx "\",\"size\":%u,"
                "\"write\":%s,\"pc\":\"0x%" PRIx64 "\"}\n",
                ++s->sequence, s->reset_generation, r->domain, r->name,
                r->base + addr, addr, size, write ? "true" : "false",
                s->cpu->env.pc);
        fflush(s->trace);
        error_report("SEP lab: unsupported %s %s at 0x%" HWADDR_PRIx
                     " (%u bytes); stopping without a fabricated response",
                     r->domain, write ? "write" : "read", r->base + addr, size);
    }
    /* A user-issued resume must not suppress the next stop request. */
    qemu_system_vmstop_request(RUN_STATE_INTERNAL_ERROR);
    return MEMTX_ERROR;
}

static MemTxResult sep_lab_read(void *opaque, hwaddr addr, uint64_t *data,
                               unsigned size, MemTxAttrs attrs)
{
    SEPLabRegion *r = opaque;
    *data = 0; /* Deterministic host output; MEMTX_ERROR marks it invalid. */
    if (r->lab->discover) {
        return sep_lab_discover(r, addr, size, false, 0);
    }
    return sep_lab_fault(r, addr, size, false);
}

static MemTxResult sep_lab_write(void *opaque, hwaddr addr, uint64_t data,
                                unsigned size, MemTxAttrs attrs)
{
    SEPLabRegion *r = opaque;
    if (r->lab->discover) {
        return sep_lab_discover(r, addr, size, true, data);
    }
    /* Values are intentionally omitted from default traces. */
    return sep_lab_fault(r, addr, size, true);
}

static const MemoryRegionOps sep_lab_ops = {
    .read_with_attrs = sep_lab_read,
    .write_with_attrs = sep_lab_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
};



/* TEMPORARY local-only debug hook (env SEP_TRAP_74430): overlay an MMIO trap
 * over the image page at PA 0x1e40074000 so every write is seen with the
 * writing PC + a short frame-pointer backtrace. Used to find who writes the
 * cap word at 0x74430 (obj_debug.c:38). Not a SEP feature; gated off by env. */
#define SEP_TRAP_PA   0x1e40528000ULL  /* roottask app-image copy (pool) */
#define SEP_TRAP_OFF  0x430   /* copy+0x420 __DATA LC; +0x10 = +0x430 */

static uint64_t sep_trap_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;
    uint64_t v = 0;
    if (off + size <= sizeof(s->trapbuf)) {
        memcpy(&v, s->trapbuf + off, size);
    }
    return v;
}

static void sep_trap_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    AppleSEPLabState *s = opaque;
    if (off + size <= sizeof(s->trapbuf)) {
        memcpy(s->trapbuf + off, &val, size);
    }
    if (off <= SEP_TRAP_OFF && off + size > SEP_TRAP_OFF) {
        CPUARMState *env = &s->cpu->env;
        uint64_t fp = env->xregs[29];
        int i;
        fprintf(s->trace,
                "{\"event\":\"trap74430\",\"pc\":\"0x%" PRIx64 "\",\"lr\":\"0x%"
                PRIx64 "\",\"off\":\"0x%" HWADDR_PRIx "\",\"size\":%u,\"value\":"
                "\"0x%" PRIx64 "\",\"word74430\":\"0x%x\",\"fp\":\"0x%" PRIx64
                "\"}\n",
                (uint64_t)env->pc, (uint64_t)env->xregs[30], off, size, val,
                *(uint32_t *)(s->trapbuf + SEP_TRAP_OFF), fp);
        for (i = 0; i < 10 && fp; i++) {
            uint64_t frame[2] = { 0, 0 };
            if (cpu_memory_rw_debug(CPU(s->cpu), fp, (uint8_t *)frame,
                                    sizeof(frame), false) != 0) {
                break;
            }
            fprintf(s->trace, "{\"event\":\"trap74430.frame\",\"i\":%d,\"fp\":"
                    "\"0x%" PRIx64 "\",\"ret\":\"0x%" PRIx64 "\"}\n",
                    i, (uint64_t)frame[0], (uint64_t)frame[1]);
            if (frame[0] <= fp) {
                break;
            }
            fp = frame[0];
        }
        fflush(s->trace);
    }
}

static const MemoryRegionOps sep_trap_ops = {
    .read = sep_trap_read,
    .write = sep_trap_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
};

/* SEPROM-equivalent record loader: lay down the tagged record directory the
 * sep64 parser (image 0x8f70) walks over the handoff region. Each 16-byte
 * record is [tag:4][count:4][offset:8]; the parser requires offsets ascending
 * and >= 0x4000, each [offset, offset+count) contained in the region size, and
 * recognizes tags CONS/CORE/CPUT/TRAC/PNIC/null. A null (count 0) record ends
 * the walk. The ranges partition the region into the kernel's initial
 * constant/core/cap-untyped/trace sub-regions. Synthetic layout: a declared
 * directory, not a measured Apple SEP memory map. */
static void sep_lab_write_region_blob(AppleSEPLabState *s)
{
    uint8_t *reg;
    struct { uint32_t tag; uint32_t count; uint64_t offset; } *rec;
    /* FourCC little-endian words as the parser builds them (image 0x8f70+). */
    const uint32_t TAG_CPUT = 0x43505554; /* "CPUT" */
    const uint32_t TAG_TRAC = 0x54524143; /* "TRAC" */
    const uint32_t TAG_CONS = 0x434f4e53; /* "CONS" */
    const uint32_t TAG_CORE = 0x434f5245; /* "CORE" */

    if (!s->seprom) {
        return;
    }
    reg = memory_region_get_ram_ptr(&s->region);
    memset(reg, 0, SEP_REGION_SIZE);
    rec = (void *)reg;
    /*
     * One directory, two parsers (kernel 0x8f70, roottask 0xd990; the kernel
     * hands the same region to the roottask via bootinfo +0x11b0/+0x11b8 at
     * 0x90a4). Record = {u32 tag, u32 size, u64 offset-from-region-base}.
     * Both require ascending, non-overlapping, region-contained records;
     * the kernel needs offset >= 0x4000 and ignores unknown tags (0x901c);
     * the roottask needs 16K-aligned offset+size (0xda6c/0xda74), maps only
     * FLAG/PNIC/TXMB and its 4-entry table at 0x174cc (0xfbe8), and asserts
     * (0xdb88 -> 0xf200) that the first payload it maps lies >= n*16 bytes
     * from the base, i.e. the directory fits ahead of the first record.
     * PNIC must be exactly 0x8000 for the roottask (0xd9cc); the kernel takes
     * it as its panic buffer (0x9050). Size 0 terminates both walks.
     */
    rec[0] = (typeof(rec[0])){ TAG_CPUT, 0x4000,  0x004000 };
    rec[1] = (typeof(rec[1])){ TAG_CONS, 0x4000,  0x008000 };
    rec[2] = (typeof(rec[2])){ TAG_CORE, 0x4000,  0x00c000 };
    rec[3] = (typeof(rec[3])){ TAG_TRAC, 0x4000,  0x010000 };
    rec[4] = (typeof(rec[4])){ 0x504e4943 /* PNIC */, 0x8000, 0x014000 };
    /* FLAG: roottask maps it; payload must list SEPO with flags bit0
     * so the TXMB default create at 0xdc30 runs (0xdbf0/0xdc2c). */
    rec[5] = (typeof(rec[5])){ 0x464c4147 /* FLAG */, 0x4000, 0x01c000 };
    rec[6] = (typeof(rec[6])){ 0x414c504f, 0x4000,  0x020000 };
    rec[7] = (typeof(rec[7])){ 0x53495049, 0x4000,  0x024000 };
    rec[8] = (typeof(rec[8])){ 0x53434f54, 0x4000,  0x028000 };
    rec[9] = (typeof(rec[9])){ 0x4e4f544f, 0x4000,  0x02c000 };
    /* rec[10] left zero: size 0 terminates both walks. 10*16 << 0x4000. */
    /*
     * FLAG payload at region+0x1c000 (roottask 0xdbcc..0xdc2c):
     *   u32 count; then count x {u32 tag, u32 flags}.
     * Must contain tag SEPO (0x5345504f) with flags bit0 set, or the
     * TXMB default create at 0xdc30 is skipped.
     */
    {
        uint32_t *flag = (uint32_t *)(reg + 0x1c000);
        flag[0] = 1;              /* count */
        flag[1] = 0x5345504f;     /* "SEPO" */
        flag[2] = 1;              /* flags: bit0 */
    }
}

/* Auto-seed the lab-proven SEPROM handoff so a seprom=on boot needs no gdb
 * pokes for BPSE / cfg / fuse / region / boot-role. Same contract as
 * modern-sep-core's sep_core_seed_handoff. Synthetic identity. */
static void sep_lab_seed_handoff(AppleSEPLabState *s)
{
    uint32_t *sram, *cfg0800, *cfg0c40, *sepmmio;

    if (!s->seprom) {
        return;
    }
    sram = memory_region_get_ram_ptr(&s->sram);
    {
        uint32_t *bpse = (uint32_t *)((uint8_t *)sram +
                                      (0x2a0210000ULL - 0x2a0200000ULL));
        bpse[0] = 0x53455042;
        bpse[2] = 1;
        bpse[0x70 / 4] = 0x528000;
        /*
         * SEPB+0x78 = size of the post-image DRAM carve used by the
         * roottask to build the FMST object (0xd7dc). Zero skips that
         * path (0xd8e4), leaves [0x6e700]=0, and the later c52c grant
         * at 0xea1c asserts on a NULL handle. 16K-aligned; 0x4000 is
         * the minimum the FMST create at 0xd87c accepts.
         */
        /*
         * With sep-stack-fix the memcfg DRAM lo window is backed, so a
         * larger FMST carve can be populated. 0x20000+ skipped PMGR without
         * DRAM lo. Entitlement's FMST size check (0x115d2c) rejects anything
         * above 32 KiB, so the stack-fix carve stops at that limit.
         */
        bpse[0x78 / 4] = s->stack_fix ? 0x8000 : 0x4000;
        /*
         * Insecure-RNG seed pair read by the roottask's
         * _liblibc_seed_insecure_rand ("s1 || s2" assert). Fixed,
         * non-secret lab constants.
         */
        bpse[0x80 / 4] = 0x5345504c;
        bpse[0x84 / 4] = 0x00000001;
        bpse[0x88 / 4] = 0x41425321;
        bpse[0x8c / 4] = 0x00000002;
    }
    cfg0800 = s->pmgr_regs; /* buffer behind sep_pmgr_ops */
    /*
     * DRAM-window sizing word: 0x9001f makes the roottask's SEP DRAM window
     * exactly [0x1e00000000, 0x1e40000000), which passes its region-table
     * consistency check at 0x10218 (0x2a3fff failed it).
     */
    cfg0800[0x408 / 4] = 0x9001f;
    cfg0800[0x410 / 4] = 0;
    cfg0800[0x418 / 4] = 0;
    cfg0c40 = memory_region_get_ram_ptr(&s->cfg0c40);
    /*
     * Memcfg words the DRAM window math uses. Lab-proven 4 / 0x4000 (ZCode
     * uses 8 / 4088 on their handoff — keep ours; size window is 0x40000 so
     * kernel-main's +0x190/+0x330/+0x4008/+0x4010 writes land in RAM).
     */
    cfg0c40[0x180 / 4] = 4;
    cfg0c40[0x1a0 / 4] = 0x4000;
    /* Fuse/XPRT already mapped at 0x2e42c0000; re-seed on soft reset. */
    {
        uint8_t *xprt = memory_region_get_ram_ptr(&s->fuse);
        uint32_t *fz = (uint32_t *)(xprt + 0x8000); /* 0x2e42c8000 */
        unsigned i;

        *(uint32_t *)(xprt + 0x4000) = 0x32b3; /* XPRT.MISC */
        fz[0] = SEP_SENTINEL;
        fz[1] = SEP_SENTINEL;
        fz[2] = SEP_SENTINEL;
        fz[3] = SEP_SENTINEL;
        for (i = 0x900 / 4; i <= 0x90c / 4; i++) {
            fz[i] = SEP_SENTINEL;
        }
        /* Antigravity / sender=3: also +0x9b0..+0x9cc */
        for (i = 0x9b0 / 4; i <= 0x9cc / 4; i++) {
            fz[i] = SEP_SENTINEL;
        }
        /* AKPUCES / TRNG window at 0x2e42dc000 (= fuse_base+0x1c000). */
        {
            uint32_t *uces = (uint32_t *)(xprt + 0x1c000);
            uces[0x00 / 4] = SEP_SENTINEL;
            uces[0x08 / 4] = SEP_SENTINEL;
            uces[0x20 / 4] = SEP_SENTINEL;
            uces[0x30 / 4] = SEP_SENTINEL;
        }
    }
    /* EXCL block: app 0x8db50 requires [+0]==[+8]==0xa55ac33c. */
    {
        uint32_t *ex = (uint32_t *)memory_region_get_ram_ptr(&s->excl);
        ex[0] = SEP_SENTINEL;
        ex[2] = SEP_SENTINEL; /* +8 */
    }
    /* AKPESAB + high AKP windows (not 0x2a0a00000). */
    {
        uint32_t *sab = (uint32_t *)memory_region_get_ram_ptr(&s->akp_sab);
        uint32_t *hi = (uint32_t *)memory_region_get_ram_ptr(&s->akp_hi);

        sab[0] = SEP_SENTINEL;
        sab[2] = SEP_SENTINEL;
        {
            uint32_t *mmt = (uint32_t *)memory_region_get_ram_ptr(&s->akp_mmt);
            mmt[0] = SEP_SENTINEL;
            mmt[2] = SEP_SENTINEL;
        }
        /* SSEAESAB at 0x2a0b00000 (start of akp_hi, overlaid by aess_mr). */
        hi[0] = SEP_SENTINEL;
        hi[2] = SEP_SENTINEL;
        memset(s->aess_regs, 0, sizeof(s->aess_regs));
        memset(s->aess_key, 0, sizeof(s->aess_key));
        s->aess_regs[0x00 / 4] = SEP_SENTINEL;
        s->aess_regs[0x08 / 4] = SEP_SENTINEL;
        /*
         * TRNG REGS live in trng_mr (W1C +0x10). Status seeds: +0x7c nibble
         * [27:24]==2 (cookie 0x120c21); +0x78 bits 19|20 (cookie 0x120c2b).
         * Missing W1C on +0x10 -> cookie 0x120c25. All three used to funnel
         * into IPC 0x7d0 panic recursion (not a real stack need).
         * sep-stack-fix stays default-off.
         */
        memset(s->trng_regs, 0, sizeof(s->trng_regs));
        /* FIFO words: Antigravity/image FIPS POST vectors (SEPD + sks). */
        s->trng_regs[0x00 / 4] = 0x34fbf246u;
        s->trng_regs[0x04 / 4] = 0xb40a6f2du;
        s->trng_regs[0x08 / 4] = 0xc56f4777u;
        s->trng_regs[0x0c / 4] = 0x5f2c2401u;
        s->trng_regs[0x10 / 4] = 0x101u; /* FIFO|DRBG ready */
        s->trng_regs[0x78 / 4] = 0x00180000u;
        s->trng_regs[0x7c / 4] = 0x02000000u;
        hi[(0x2a0bc1800ULL - 0x2a0b00000ULL) / 4] = 0x3;
    }
    /* Platform sentinels (plat RAM base 0x2a0d80000, size 0x100000). */
    {
        uint32_t *plat = (uint32_t *)memory_region_get_ram_ptr(&s->plat);
        uint32_t *tbase;

        plat[(0x2a0dd8008ULL - 0x2a0d80000ULL) / 4] = SEP_SENTINEL;
        plat[(0x2a0dc0010ULL - 0x2a0d80000ULL) / 4] = 0x101;
        /* 0x2a0bc1800 is below plat base — seed via discover RAM? skip; rare. */
        tbase = &plat[(0x2a0e40000ULL - 0x2a0d80000ULL) / 4];
        /* +0x400/+0x410 shadowed by timer IO; timer_read returns sentinel.
         * Higher offsets are visible through this RAM (prio 0). */
        tbase[0x8000 / 4] = 0x40000; /* shadowed by key_fcfg_mr */
        s->key_fcfg_8000 = 0x40000;
        tbase[0xc000 / 4] = 0x5;
        tbase[0x10008 / 4] = 0x5;
        tbase[0x10010 / 4] = 0x4;
    }
    sepmmio = memory_region_get_ram_ptr(&s->sepmmio);
    /*
     * ASC-v6 A2I_RECV at 0x2a2404810 (boot/shmbuf msg, low byte 0xfe).
     * Same seed the kernel's 0x7cf8 path decodes into region base/size.
     */
    /*
     * Platform/shmbuf descriptor at 0x2a2400000 (sep64 0x7cf8):
     *   spin while bit17 of +0x4110 is SET (zero-filled RAM passes);
     *   then u64 at +0x4810 = (base>>12)<<32 | (size>>12)<<16 | 0xfe,
     *        u64 at +0x4818 = flags (0 ok).
     * Not a live ASC doorbell yet — one-shot boot descriptor.
     */
    sepmmio[0x404110 / 4] = 0; /* bit17 clear */
    sepmmio[0x404810 / 4] = 0x040000fe;
    sepmmio[0x404814 / 4] = 0x10000000;
    sepmmio[0x404818 / 4] = 0;
    sepmmio[0x40481c / 4] = 0;
    /* boot-role = BPSE|1 (cold build path); ready bit stays 1. */
    s->cpu->env.apple_modern_sep_store[14] = 0x2a0210000ULL | 1ULL;
    s->cpu->env.apple_modern_sep_store[13] = 1ULL;
    sep_lab_write_region_blob(s);
}

static void sep_lab_reset(void *opaque)
{
    AppleSEPLabState *s = opaque;

    s->stack_fix_fills = 0;
    s->stack_fix_next_pa = 0;
    s->ext_irq_mask = 0xffffffffu;
    s->ext_irq_edge = 0;
    s->pmgr28000_latched = false;
    s->pmgr2c000_latched = false;
    s->trng_pending = false;
    s->sars_init_notified = false;
    s->xart_e0_send_active = false;
    s->e0_receive_active = false;
    s->e0_receive_pc = 0;
    s->notify_svc_active = 0;
    s->notify_svc_pc = 0;

    cpu_reset(CPU(s->cpu));
    cpu_set_pc(CPU(s->cpu), s->entry);
    sep_lab_seed_handoff(s);
    if (s->sep_inject) {
        sep_inject_reset_state(s);
    }
    /*
     * Entry stub (image 0x4010/0x40fc): x1 is the Mach-O copy source.
     * Peer (Antigravity): x1 = SEP_KRAM_BASE so 0x4000 bytes land at
     * 0x1e4001c000. Harmless when the image base is not MH_MAGIC_64.
     */
    if (s->seprom) {
        s->cpu->env.xregs[1] = SEP_KRAM_BASE;
    }
    s->faulted = false;
    s->reset_generation++;
    sep_lab_trace_reset(s);
}



static void sep_lab_exclog_dump_ring(AppleSEPLabState *s, const char *why)
{
    unsigned i;

    error_report("SEP lab: %s — last SVCs (oldest→newest):", why);
    for (i = 0; i < 64; i++) {
        uint64_t *e = s->exclog_ring[(s->exclog_ring_pos + i) % 64];

        if (!e[0]) {
            continue;
        }
        error_report("  svc pc=0x%" PRIx64 " lr=0x%" PRIx64 " x0=0x%" PRIx64
                     " x1=0x%" PRIx64 " x2=0x%" PRIx64 " x3=0x%" PRIx64
                     " x4=0x%" PRIx64 " x5=0x%" PRIx64 " x6=0x%" PRIx64
                     " x7=0x%" PRIx64 " bt=[0x%" PRIx64 ",0x%" PRIx64
                     ",0x%" PRIx64 ",0x%" PRIx64 "]",
                     e[0], e[1], e[2], e[3], e[4], e[5],
                     e[8], e[9], e[10], e[11],
                     e[12], e[13], e[14], e[15]);
    }
}

/* J410 24A437 phase-2 research compatibility: observe the sars init/e0 IPC
 * without changing guest objects or manufacturing SVC results. */
#define SEP_SARS_INIT_NOTIFY_OBJ 0xffffffff00574160ULL
#define SEP_SARS_OWNER_TCB       0xffffffff0059e800ULL
#define SEP_IPC_E0_OBJ           0xffffffff005700e0ULL
#define SEP_XART_E0_SEND_PC      0x3981aca38ULL

static uint64_t sep_lab_decode_ipc_object(CPUState *cs, uint64_t slot,
                                          unsigned expected_type)
{
    uint64_t header = 0;
    uint32_t encoded;

    if (cpu_memory_rw_debug(cs, slot, (uint8_t *)&header,
                            sizeof(header), false) != 0 ||
        (header >> 58) != expected_type) {
        return 0;
    }
    encoded = (uint32_t)header << 4;
    if (!encoded) {
        return 0;
    }
    return (uint64_t)(-(int64_t)encoded);
}

/* (Translation of kernel VAs is done by sep_lab_kernel_rw; sepOS uses a
 * 64 KiB TTBR1 granule with T1SZ=32, so a hand-rolled 4 KiB walk reads the
 * wrong pages. QEMU's own walk handles the geometry.) */

/* The EL0 SVC hook cannot use cpu_memory_rw_debug on kernel (TTBR1-region)
 * addresses: sepOS sets TCR_EL1.E0PD1 (bit 56), QEMU's debug walk honours
 * E0PD for user regimes, and every kernel-VA translation faults. Flip the
 * bit off around the access; the debug walk is a software table walk that
 * neither consults nor pollutes the TLB, and no guest code runs in between,
 * so the kernel cannot observe the change. */
static int sep_lab_kernel_rw(AppleSEPLabState *s, uint64_t va, void *buf,
                             int len, bool is_write)
{
    CPUARMState *env = &s->cpu->env;
    uint64_t saved_tcr = env->cp15.tcr_el[1];
    int rc;

    env->cp15.tcr_el[1] = saved_tcr & ~(1ULL << 56);
    rc = cpu_memory_rw_debug(CPU(s->cpu), va, buf, len, is_write);
    env->cp15.tcr_el[1] = saved_tcr;
    return rc;
}

static bool sep_lab_el1_read_u64(AppleSEPLabState *s, uint64_t va,
                                 uint64_t *value)
{
    return sep_lab_kernel_rw(s, va, value, sizeof(*value), false) == 0;
}

static bool sep_lab_el1_write_u64(AppleSEPLabState *s, uint64_t va,
                                  uint64_t value)
{
    return sep_lab_kernel_rw(s, va, &value, sizeof(value), true) == 0;
}

/* P0: post the initial pending bit on the sars init obj_notify through the
 * E0PD1-flipped debug translation. The earlier attempt went through
 * cpu_memory_rw_debug from the EL0 SVC hook and never landed. */
/* One-shot thread map: scan the kernel object region for TCB-shaped
 * objects (saved pc at +0xf8 in user-VA range, wait state at +0x410)
 * and report what each is parked on, with the target's service name. */
static void sep_lab_dump_tcbmap(AppleSEPLabState *s)
{
    uint64_t va;
    unsigned found = 0;

    for (va = 0xffffffff00580000ULL;
         va < 0xffffffff00700000ULL && found < 80; va += 0x400) {
        uint64_t pc = 0, wait = 0, parked = 0, name = 0;

        if (!sep_lab_el1_read_u64(s, va + 0xf8, &pc) || pc < 0x10000 ||
            pc > 0x1000000000000ULL) {
            continue;
        }
        if (!sep_lab_el1_read_u64(s, va + 0x410, &wait) ||
            (wait & ~0xffffULL) || wait > 0xff) {
            continue;
        }
        sep_lab_el1_read_u64(s, va + 0x3f8, &parked);
        if (parked >= 0xffffffff00000000ULL &&
            parked < 0xffffffff01000000ULL) {
            sep_lab_el1_read_u64(s, parked + 0x10, &name);
        }
        error_report("SEP e0 tcb: va=0x%" PRIx64 " pc=0x%" PRIx64
                     " wait=0x%" PRIx64 " parked=0x%" PRIx64
                     " name=0x%08" PRIx32, va, pc, wait, parked,
                     (uint32_t)name);
        if ((wait & 0xff) == 0x81 && parked) {
            uint64_t m0 = 0, m1 = 0, m2 = 0, m3 = 0;

            sep_lab_el1_read_u64(s, va + 0x10, &m0);
            sep_lab_el1_read_u64(s, va + 0x18, &m1);
            sep_lab_el1_read_u64(s, va + 0x20, &m2);
            sep_lab_el1_read_u64(s, va + 0x28, &m3);
            error_report("SEP e0 tcb: msg %#lx %#lx %#lx %#lx",
                         m0, m1, m2, m3);
        }
        found++;
    }
    error_report("SEP e0 tcb: scan found %u threads", found);
    /* IPC object table: endpoints at 0x570000+i*0x20, notifications above.
     * Print slots with any live word; +0x10 is the 4-char service name. */
    {
        uint64_t va;

        for (va = 0xffffffff00570000ULL; va < 0xffffffff00580000ULL;
             va += 0x20) {
            uint64_t w0 = 0, w8 = 0, wn = 0;

            sep_lab_el1_read_u64(s, va, &w0);
            sep_lab_el1_read_u64(s, va + 8, &w8);
            sep_lab_el1_read_u64(s, va + 0x10, &wn);
            if (!w0 && !w8 && !wn) {
                continue;
            }
            error_report("SEP e0 obj: %#llx +0=%#llx +8=%#llx name=%#llx",
                         va, w0, w8, wn);
        }
    }
}

static void sep_lab_sars_dump_walk(AppleSEPLabState *s)
{
    static const struct {
        const char *name;
        uint64_t va;
    } probe[] = {
        { "current", 0xffffffff00020be0ULL },      /* current-thread ptr */
        { "tcb.pc", 0xffffffff0059e8f8ULL },       /* sars TCB + 0xf8 */
        { "tcb.wait", 0xffffffff0059ec10ULL },     /* sars TCB + 0x410 */
        { "tcb.parked_on", 0xffffffff0059ebf8ULL },/* sars TCB + 0x3f8 */
        { "e0+0", SEP_IPC_E0_OBJ },
        { "e0+8", SEP_IPC_E0_OBJ + 8 },
        { "e0+0x10", SEP_IPC_E0_OBJ + 0x10 },
        { "notify+0", SEP_SARS_INIT_NOTIFY_OBJ },
        { "notify+8", SEP_SARS_INIT_NOTIFY_OBJ + 8 },
        { "notify+0x10", SEP_SARS_INIT_NOTIFY_OBJ + 0x10 },
        { "180+0", 0xffffffff00570180ULL },
        { "180+8", 0xffffffff00570188ULL },
        { "180+0x10", 0xffffffff00570190ULL },
        { "80+0x10", 0xffffffff00570090ULL },      /* name of ep 0x...080 */
    };
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(probe); i++) {
        uint64_t val = 0;
        bool ok = sep_lab_el1_read_u64(s, probe[i].va, &val);

        error_report("SEP e0 probe: %s=0x%" PRIx64 "%s", probe[i].name, val,
                     ok ? "" : " (unreadable)");
    }
    /* Walk one level of the parked chain: whoever is parked on e0 and
     * whatever the sars TCB is parked on, then that object's name. */
    {
        uint64_t head = 0, parked = 0;
        static const struct {
            const char *name;
            uint64_t off;
        } head_fields[] = {
            { "e0.waiter.pc", 0xf8 },
            { "e0.waiter.wait", 0x410 },
            { "e0.waiter.parked_on", 0x3f8 },
        };
        unsigned k;

        if (sep_lab_el1_read_u64(s, SEP_IPC_E0_OBJ, &head) && head) {
            for (k = 0; k < ARRAY_SIZE(head_fields); k++) {
                uint64_t val = 0;

                sep_lab_el1_read_u64(s, head + head_fields[k].off, &val);
                error_report("SEP e0 probe: %s=0x%" PRIx64,
                             head_fields[k].name, val);
            }
        }
        if (sep_lab_el1_read_u64(s, 0xffffffff0059ebf8ULL, &parked) &&
            parked) {
            uint64_t val = 0;

            sep_lab_el1_read_u64(s, parked + 0x10, &val);
            error_report("SEP e0 probe: sars.parked.name=0x%" PRIx64, val);
            sep_lab_el1_read_u64(s, parked, &val);
            error_report("SEP e0 probe: sars.parked.head=0x%" PRIx64, val);
        }
    }
    sep_lab_dump_tcbmap(s);
}

static void sep_lab_sars_post_notify(AppleSEPLabState *s)
{
    uint64_t old = 0, verify = 0;

    if (s->sars_init_notified) {
        return;
    }
    s->sars_init_notified = true;

    if (!sep_lab_el1_read_u64(s, SEP_SARS_INIT_NOTIFY_OBJ, &old)) {
        error_report("SEP e0: sars notify read failed");
        return;
    }
    if (old >> 58) {
        /* +0 carries an object type header, not a pending mask. */
        error_report("SEP e0: sars notify+0 is a header (0x%" PRIx64
                     "); pending bit not written", old);
        return;
    }
    if (!sep_lab_el1_write_u64(s, SEP_SARS_INIT_NOTIFY_OBJ, old | 1)) {
        error_report("SEP e0: sars notify write failed");
        return;
    }
    sep_lab_el1_read_u64(s, SEP_SARS_INIT_NOTIFY_OBJ, &verify);
    error_report("SEP e0: sars notify pending posted old=0x%" PRIx64
                 " new=0x%" PRIx64 " verify=0x%" PRIx64, old, old | 1,
                 verify);
}

static void sep_lab_sars_log_state(AppleSEPLabState *s)
{
    static const struct {
        const char *name;
        uint64_t addr;
    } fields[] = {
        { "e0+0", SEP_IPC_E0_OBJ },
        { "e0+8", SEP_IPC_E0_OBJ + 8 },
        { "notify+0", SEP_SARS_INIT_NOTIFY_OBJ },
        { "notify+8", SEP_SARS_INIT_NOTIFY_OBJ + 8 },
        { "tcb.saved_pc", SEP_SARS_OWNER_TCB + 0xf8 },
        { "tcb.wait_state", SEP_SARS_OWNER_TCB + 0x410 },
    };
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(fields); i++) {
        uint64_t value = 0;

        if (sep_lab_el1_read_u64(s, fields[i].addr, &value)) {
            error_report("SEP e0 state: %s=0x%" PRIx64,
                         fields[i].name, value);
        } else {
            error_report("SEP e0 state: %s unreadable", fields[i].name);
        }
    }
}

/*
 * Synthetic server for the endpoints whose real server thread is itself
 * parked in a startup connect (skgs, TREx, sks, ARTM, scrd, sbio, sse).
 * Completes one queued sender exactly as the kernel's receive-match does:
 * dequeue from the endpoint, clear the wait word, insert into the priority
 * run queue (kernel 0xd1e4 recipe, w1=0). Off by default; SEP_SYNTH_SERVE=1.
 */
static bool sep_lab_synth_serve_one(AppleSEPLabState *s)
{
    static const uint64_t eps[] = {
        0xffffffff00570280ULL, /* skgs */
        0xffffffff00570120ULL, /* TREx */
        0xffffffff00570180ULL, /* sks  */
        0xffffffff00570100ULL, /* ARTM */
        0xffffffff00570140ULL, /* scrd */
        0xffffffff005701c0ULL, /* sbio */
        0xffffffff005701e0ULL, /* sse  */
        0xffffffff005700e0ULL, /* e0 "sars" (SEP_SYNTH_E0 only) */
    };
    static unsigned synth_cands;
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(eps); i++) {
        uint64_t ep = eps[i];
        uint64_t head = 0, tailw = 0, wait = 0, next = 0;
        uint64_t prio_w = 0, qhead = 0, prev = 0, stamp = 0, bmp = 0;
        uint64_t tcb, qslot, bslot;
        unsigned np;
        uint8_t prio;

        if (ep == SEP_IPC_E0_OBJ && !s->synth_e0) {
            continue;
        }
        if (!sep_lab_el1_read_u64(s, ep, &head) || !head) {
            continue;
        }
        if (!sep_lab_el1_read_u64(s, ep + 8, &tailw)) {
            continue;
        }
        if (synth_cands < 24 && !(tailw & 1)) {
            uint64_t dwait = 0;
            bool wok = sep_lab_el1_read_u64(s, (head & ~3ULL) + 0x410,
                                            &dwait);
            uint8_t dprio = 0;
            bool pok = sep_lab_kernel_rw(s, (head & ~3ULL) + 0x3e5,
                                         &dprio, 1, false) == 0;

            synth_cands++;
            error_report("SEP synth: send-cand ep=0x%" PRIx64
                         " head=0x%" PRIx64 " tail=0x%" PRIx64
                         " wait_ok=%d wait=0x%" PRIx64 " prio_ok=%d"
                         " prio=0x%x", ep, head, tailw, wok, dwait,
                         pok, dprio);
        }
        if (tailw & 1) {
            continue; /* a real receiver is queued; the kernel will match */
        }
        tcb = head & ~3ULL;
        if (tcb < 0xffffffff00548000ULL || tcb > 0xffffffff00700000ULL) {
            if (synth_cands < 30) error_report("SEP synth: fail range");
            continue;
        }
        if (!sep_lab_el1_read_u64(s, tcb + 0x410, &wait) ||
            ((wait & 0xff) != 0x81 && (wait & 0xff) != 0x01 &&
             (wait & 0xff) != 0x82 && (wait & 0xff) != 0x02)) {
            if (synth_cands < 30) error_report("SEP synth: fail wait");
            continue;
        }
        /* Read the priority before any guest write. The byte-sized debug
         * access is unreliable here; read the containing u64 and extract
         * byte 5 (all these connect senders run at priority 0x64). */
        {
            uint64_t wp = 0;

            if (sep_lab_el1_read_u64(s, tcb + 0x3e0, &wp)) {
                prio = (wp >> 40) & 0xff;
            }
            if (!prio) {
                prio = 0x64;
            }
        }
        /* dequeue the head (kernel 0xf58c semantics) */
        sep_lab_el1_read_u64(s, tcb + 0x408, &next);
        sep_lab_el1_write_u64(s, ep, next);
        if (next) {
            sep_lab_el1_write_u64(s, next + 0x400, 0);
        }
        if ((tailw & ~3ULL) == tcb) {
            sep_lab_el1_write_u64(s, ep + 8, tailw & 3);
        }
        sep_lab_el1_write_u64(s, tcb + 0x400, 0);
        sep_lab_el1_write_u64(s, tcb + 0x408, 0);
        sep_lab_el1_write_u64(s, tcb + 0x3f8, 0);
        sep_lab_el1_write_u64(s, tcb + 0x410, 0);
        sep_lab_el1_write_u64(s, tcb, 0);
        if ((wait & 0xff) == 0x82 || (wait & 0xff) == 0x02) {
            sep_lab_el1_write_u64(s, tcb + 0x10, 0); /* call reply word */
        }
        np = (~prio) & 0xff;
        qslot = 0xffffffff00021040ULL + (uint64_t)np * 8;
        sep_lab_el1_read_u64(s, qslot, &qhead);
        if (qhead) {
            sep_lab_el1_read_u64(s, qhead + 0x3d0, &prev);
            sep_lab_el1_write_u64(s, prev + 0x3d8, tcb);
            sep_lab_el1_write_u64(s, tcb + 0x3d0, prev);
            sep_lab_el1_write_u64(s, tcb + 0x3d8, qhead);
            sep_lab_el1_write_u64(s, qhead + 0x3d0, tcb);
        } else {
            sep_lab_el1_write_u64(s, tcb + 0x3d0, tcb);
            sep_lab_el1_write_u64(s, tcb + 0x3d8, tcb);
            sep_lab_el1_write_u64(s, qslot, tcb);
            bslot = 0xffffffff00021040ULL + (((uint64_t)np >> 3) & 0x18) +
                    0x808;
            sep_lab_el1_read_u64(s, bslot, &bmp);
            sep_lab_el1_write_u64(s, bslot, bmp | (1ULL << (np & 0x3f)));
        }
        sep_lab_el1_read_u64(s, 0xffffffff00021870ULL, &stamp);
        sep_lab_el1_write_u64(s, tcb + 0x3e8, stamp);
        (void)prio_w;
        {
            uint64_t chk = 0, cw = 0;

            sep_lab_el1_read_u64(s, ep, &chk);
            sep_lab_el1_read_u64(s, ep + 8, &cw);
            error_report("SEP synth: served ep=0x%" PRIx64 " tcb=0x%" PRIx64
                         " wait=0x%" PRIx64 " ep_now=0x%" PRIx64
                         " tail_now=0x%" PRIx64, ep, tcb, wait, chk, cw);
        }
        return true;
    }
    return false;
}

/*
 * P1: kick a parked receiver so its receive re-arms and can match senders
 * already queued on the same endpoint (the kernel never re-checks a parked
 * receiver). Env-gated by SEP_WAKE_SEPD=1; one-shot per TCB per boot.
 */
static void sep_lab_wake_receiver(AppleSEPLabState *s, uint64_t tcb)
{
    uint64_t wait = 0, prio_w = 0, qhead = 0, prev = 0, stamp = 0, bmp = 0;
    uint64_t qslot, bslot, wp = 0;
    unsigned np;
    uint8_t prio = 0;

    if (!sep_lab_el1_read_u64(s, tcb + 0x410, &wait) ||
        (wait & 0xff) != 0x84) {
        return;
    }
    if (sep_lab_el1_read_u64(s, tcb + 0x3e0, &wp)) {
        prio = (wp >> 40) & 0xff;
    }
    if (!prio) {
        prio = 0x64;
    }
    np = (~prio) & 0xff;
    qslot = 0xffffffff00021040ULL + (uint64_t)np * 8;
    sep_lab_el1_read_u64(s, qslot, &qhead);
    if (qhead) {
        sep_lab_el1_read_u64(s, qhead + 0x3d0, &prev);
        sep_lab_el1_write_u64(s, prev + 0x3d8, tcb);
        sep_lab_el1_write_u64(s, tcb + 0x3d0, prev);
        sep_lab_el1_write_u64(s, tcb + 0x3d8, qhead);
        sep_lab_el1_write_u64(s, qhead + 0x3d0, tcb);
    } else {
        sep_lab_el1_write_u64(s, tcb + 0x3d0, tcb);
        sep_lab_el1_write_u64(s, tcb + 0x3d8, tcb);
        sep_lab_el1_write_u64(s, qslot, tcb);
        bslot = 0xffffffff00021040ULL + (((uint64_t)np >> 3) & 0x18) + 0x808;
        sep_lab_el1_read_u64(s, bslot, &bmp);
        sep_lab_el1_write_u64(s, bslot, bmp | (1ULL << (np & 0x3f)));
    }
    sep_lab_el1_read_u64(s, 0xffffffff00021870ULL, &stamp);
    sep_lab_el1_write_u64(s, tcb + 0x3e8, stamp);
    sep_lab_el1_write_u64(s, tcb + 0x410, 0);
    sep_lab_el1_write_u64(s, tcb + 0x3f8, 0);
    sep_lab_el1_write_u64(s, tcb, 0);
    (void)prio_w;
    error_report("SEP p1: woke receiver tcb=0x%" PRIx64 " (was wait=0x%"
                 PRIx64 ")", tcb, wait);
}

static void sep_lab_sars_ipc_pre_hook(ARMCPU *cpu, void *opaque)
{
    AppleSEPLabState *s = opaque;
    CPUARMState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    unsigned svc;
    uint64_t obj;

    if (extract32(env->pstate, 2, 2) != 0 || !env->aarch64 ||
        cs->exception_index != EXCP_SWI) {
        return;
    }
    svc = (unsigned)(env->exception.syndrome & 0xffff);
    {
        static bool sepd_kicked;
        const char *kick_env = getenv("SEP_WAKE_SEPD");

        if (!sepd_kicked && kick_env && *kick_env && strcmp(kick_env, "0")) {
            uint64_t w = 0, head = 0, tailw = 0;

            /* Only when the registration senders are queued and no receiver
             * bit is set: waking the parked receiver then lets its next
             * receive match them. */
            if (s->pmgr2c_count >= 60 &&
                sep_lab_el1_read_u64(s, 0xffffffff0059c000ULL + 0x410, &w) &&
                (w & 0xff) == 0x84) {
                sepd_kicked = true;
                sep_lab_wake_receiver(s, 0xffffffff0059c000ULL);
            }
        }
    }
    if (s->synth_serve) {
        static bool synth_seen;

        if (!synth_seen) {
            synth_seen = true;
            error_report("SEP synth: hook active");
        }
        sep_lab_synth_serve_one(s);
        /* Kick the shared reply notification: a waiter polling it then sees
         * pending and proceeds (the mechanism P0 asked for, applied
         * continuously so reply-waits do not deadlock). */
        {
            uint64_t npend = 0;

            if (sep_lab_el1_read_u64(s, SEP_SARS_INIT_NOTIFY_OBJ,
                                     &npend) && !(npend >> 58) &&
                !(npend & 1)) {
                sep_lab_el1_write_u64(s, SEP_SARS_INIT_NOTIFY_OBJ,
                                      npend | 1);
            }
        }
    }
    if (svc == 0) {
        obj = sep_lab_decode_ipc_object(cs, env->xregs[0], 6);
        if (obj != SEP_IPC_E0_OBJ) {
            return;
        }
        if (env->xregs[1] == 0 && env->pc == SEP_XART_E0_SEND_PC) {
            s->xart_e0_send_active = true;
            error_report("SEP e0: xART selector 0x11179 send entered");
            sep_lab_sars_log_state(s);
            sep_lab_sars_dump_walk(s);
            sep_lab_sars_post_notify(s);
        } else if (env->xregs[1] == 3) {
            s->e0_receive_active = true;
            s->e0_receive_pc = env->pc;
            error_report("SEP e0: receive entered pc=0x%" PRIx64, env->pc);
        }
        return;
    }
    if (svc < 2 || svc > 4) {
        return;
    }
    obj = sep_lab_decode_ipc_object(cs, env->xregs[0], 6);
    if (!obj) {
        obj = sep_lab_decode_ipc_object(cs, env->xregs[0], 8);
    }
    if (obj != SEP_IPC_E0_OBJ && obj != SEP_SARS_INIT_NOTIFY_OBJ &&
        obj != 0xffffffff00570040ULL /* SEPD main ep */ &&
        obj != 0xffffffff00570080ULL /* dxio ep */ &&
        obj != 0xffffffff00570280ULL /* skgs ep */ &&
        obj != 0xffffffff005704c0ULL /* PMGR service ep */) {
        return;
    }
    error_report("SEP ipc: pc=0x%" PRIx64 " svc=%u x0=0x%" PRIx64
                 " x1=0x%" PRIx64 " x2=0x%" PRIx64 " x3=0x%" PRIx64,
                 env->pc, svc, env->xregs[0], env->xregs[1],
                 env->xregs[2], env->xregs[3]);
    if (obj == SEP_SARS_INIT_NOTIFY_OBJ) {
        s->notify_svc_active = svc;
        s->notify_svc_pc = env->pc;
    }
    if (svc == 3 && obj == SEP_IPC_E0_OBJ) {
        s->e0_receive_active = true;
        s->e0_receive_pc = env->pc;
        error_report("SEP e0: receive entered pc=0x%" PRIx64, env->pc);
    }
}

static void sep_lab_sars_ipc_post_hook(ARMCPU *cpu, void *opaque)
{
    AppleSEPLabState *s = opaque;
    CPUARMState *env = &cpu->env;

    if (extract32(env->pstate, 2, 2) != 0 || !env->aarch64) {
        return;
    }
    if (s->xart_e0_send_active && env->pc == SEP_XART_E0_SEND_PC) {
        s->xart_e0_send_active = false;
        error_report("SEP e0: xART selector 0x11179 send returned x0=0x%"
                     PRIx64, env->xregs[0]);
    }
    if (s->notify_svc_active && env->pc == s->notify_svc_pc) {
        error_report("SEP e0: notify svc=%u returned x0=0x%" PRIx64
                     " x1=0x%" PRIx64, s->notify_svc_active,
                     env->xregs[0], env->xregs[1]);
        s->notify_svc_active = 0;
        s->notify_svc_pc = 0;
    }
    if (s->e0_receive_active && env->pc == s->e0_receive_pc) {
        s->e0_receive_active = false;
        error_report("SEP e0: receive returned x0=0x%" PRIx64,
                     env->xregs[0]);
    }
}

static void sep_lab_exclog_hook(ARMCPU *cpu, void *opaque)
{
    AppleSEPLabState *s = opaque;
    CPUARMState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    int el = extract32(env->pstate, 2, 2);

    if (el != 0 || !(env->aarch64)) {
        return;
    }
    if (cs->exception_index == EXCP_SWI) {
        uint64_t *e;
        bool hit = false;
        int r;

        if (env->pc == 0xb3b4 ||
            ((env->xregs[0] & 0x3fff) == 0 && env->xregs[1] <= 1 &&
             env->xregs[3] == 1 && env->xregs[2] < 0x80)) {
            static char conbuf[256];
            static unsigned conpos;
            char ch = (char)(env->xregs[2] & 0xff);

            if (env->pc == 0xb3b4 && s->exclog_svc_hits == 0) {
                s->exclog_svc_hits = 1;
                sep_lab_exclog_dump_ring(s, "first roottask panic putc");
            }
            if (env->xregs[1] == 0 && ch >= 0x20 && ch < 0x7f) {
                if (conpos < sizeof(conbuf) - 1) {
                    conbuf[conpos++] = ch;
                }
            }
            if (env->xregs[1] == 1 || ch == '\n' || conpos >= sizeof(conbuf) - 1) {
                if (conpos > 0) {
                    conbuf[conpos] = '\0';
                    error_report("SEP con: %s", conbuf);
                    conpos = 0;
                }
            }
            return;
        }
        if (env->pc < 0x20000) {
            return;
        }
        e = s->exclog_ring[s->exclog_ring_pos];
        memset(e, 0, 16 * sizeof(uint64_t));
        e[0] = env->pc; e[1] = env->xregs[30];
        e[2] = env->xregs[0]; e[3] = env->xregs[1];
        e[4] = env->xregs[2]; e[5] = env->xregs[3];
        e[6] = env->xregs[16]; e[7] = env->xregs[27];
        e[8] = env->xregs[4]; e[9] = env->xregs[5];
        e[10] = env->xregs[6]; e[11] = env->xregs[7];
        {
            uint64_t fp = env->xregs[29];
            int fi;
            for (fi = 0; fi < 4 && fp && (fp & 7) == 0; fi++) {
                uint64_t fr[2] = { 0, 0 };
                if (cpu_memory_rw_debug(cs, fp, (uint8_t *)fr,
                                        sizeof(fr), false) != 0) {
                    break;
                }
                e[12 + fi] = fr[1] & 0xffffffffffffULL;
                if (fr[0] <= fp || fr[0] - fp > 0x10000) {
                    break;
                }
                fp = fr[0];
            }
        }
        s->exclog_ring_pos = (s->exclog_ring_pos + 1) % 64;
        if ((env->exception.syndrome & 0xffff) < 32 &&
            (s->exclog_svc_mask & BIT(env->exception.syndrome & 0xffff))) {
            uint64_t ipc[16] = { 0 };

            if (cpu_memory_rw_debug(cs, env->cp15.tpidrro_el[0],
                                    (uint8_t *)ipc, sizeof(ipc), false) != 0) {
                memset(ipc, 0, sizeof(ipc));
            }
            error_report("SEP svc%u: pc=0x%" PRIx64 " x0=0x%" PRIx64
                         " x1=0x%" PRIx64 " x2=0x%" PRIx64 " x3=0x%" PRIx64
                         " ipc=[0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64
                         ",0x%" PRIx64 ",0x%" PRIx64 "]",
                         (unsigned)(env->exception.syndrome & 0xffff), env->pc,
                         env->xregs[0], env->xregs[1], env->xregs[2],
                         env->xregs[3], ipc[0], ipc[1], ipc[2], ipc[3], ipc[4]);
            if ((ipc[3] & 0xffffffff) == 0x42be) {
                error_report("SEP PMGR payload: [0x%" PRIx64 ",0x%" PRIx64
                             ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64
                             ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64
                             ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 "]",
                             ipc[5], ipc[6], ipc[7], ipc[8], ipc[9], ipc[10],
                             ipc[11], ipc[12], ipc[13], ipc[14], ipc[15]);
            }
        }
        if (s->exclog_max > 32 && (env->pc >> 24) == 0x192) {
            uint64_t sl = 0x1922fc000ULL;
            error_report("SEP sks svc: pc=+0x%" PRIx64 " lr=+0x%" PRIx64
                         " x0=0x%" PRIx64 " x1=0x%" PRIx64 " x2=0x%" PRIx64
                         " x3=0x%" PRIx64 " bt=[+0x%" PRIx64 ",+0x%" PRIx64
                         ",+0x%" PRIx64 ",+0x%" PRIx64 "]",
                         e[0] - sl, e[1] - sl, e[2], e[3], e[4], e[5],
                         e[12] ? e[12] - sl : 0, e[13] ? e[13] - sl : 0,
                         e[14] ? e[14] - sl : 0, e[15] ? e[15] - sl : 0);
        }
        for (r = 0; r <= 8; r++) {
            if (env->xregs[r] == 0x7d0) {
                hit = true;
            }
        }
        if (hit && s->exclog_svc_hits++ < 2) {
            sep_lab_exclog_dump_ring(s, "SVC with 0x7d0");
        }
        return;
    }
    if (cs->exception_index == EXCP_IRQ ||
        cs->exception_index == EXCP_FIQ ||
        cs->exception_index == EXCP_VIRQ ||
        cs->exception_index == EXCP_VFIQ) {
        return;
    }
    if (s->exclog_n == 0) {
        sep_lab_exclog_dump_ring(s, "first EL0 abort/UDF");
    }
    if (s->exclog_n++ < s->exclog_max) {
        error_report("SEP lab: EL0 exc %d syn=0x%" PRIx64 " pc=0x%"
                     PRIx64 " far=0x%" PRIx64 " sp0=0x%" PRIx64 " lr=0x%"
                     PRIx64 " x0=0x%" PRIx64 " x1=0x%" PRIx64 " x27=0x%"
                     PRIx64 " ttbr0=0x%" PRIx64,
                     cs->exception_index, (uint64_t)env->exception.syndrome,
                     env->pc, (uint64_t)env->exception.vaddress, env->sp_el[0],
                     env->xregs[30], env->xregs[0], env->xregs[1],
                     env->xregs[27], env->cp15.ttbr0_el[1]);
    }
}

static void sep_lab_exclog_init(AppleSEPLabState *s)
{
    const char *env = getenv("SEP_CORE_EXCLOG");
    uint64_t n;

    if (getenv("SEP_CORE_EXCLOG_SVC0")) {
        s->exclog_svc_mask |= BIT(0);
    }
    if (getenv("SEP_CORE_EXCLOG_SVC1")) {
        s->exclog_svc_mask |= BIT(1);
    }
    if (getenv("SEP_CORE_EXCLOG_SVC2")) {
        s->exclog_svc_mask |= BIT(2);
    }
    if (getenv("SEP_CORE_EXCLOG_SVC3")) {
        s->exclog_svc_mask |= BIT(3);
    }
    if (getenv("SEP_CORE_EXCLOG_SVC5")) {
        s->exclog_svc_mask |= BIT(5);
    }
    if (!env || !*env || qemu_strtou64(env, NULL, 0, &n) < 0 || !n) {
        if (s->exclog_svc_mask) {
            s->exclog_max = 1;
            arm_register_pre_el_change_hook(s->cpu, sep_lab_exclog_hook, s);
            error_report("SEP lab: SVC trace mask=%#x", s->exclog_svc_mask);
        }
        return;
    }
    s->exclog_max = (uint32_t)n;
    arm_register_pre_el_change_hook(s->cpu, sep_lab_exclog_hook, s);
    error_report("SEP lab: SEP_CORE_EXCLOG=%u (EL0 exception log; svc mask=%#x)",
                 s->exclog_max, s->exclog_svc_mask);
}

/*
 * File offsets inside sepos.j410 image for EPControl (Mach-O @ 0x74000,
 * __TEXT vmaddr 0x110000). Patches the in-kram copy only.
 */
#define SEP_EP_FILE          0x74000u
#define SEP_EP_TEXT_VA       0x110000u
#define SEP_EP_FO(va)        (SEP_EP_FILE + ((va) - SEP_EP_TEXT_VA))
#define SEP_EP_START_ALL     0x118498u
#define SEP_EP_START_EXIT    0x118524u   /* b #reply → exit stub when phase2 */
#define SEP_EP_IPC_REPLY     0x11ff2cu   /* original b target at 0x118524 */
#define SEP_EP_CREATE_RET    0x118e6cu   /* create-fn retab → b trampoline */
#define SEP_EP_TRAMP         0x123000u   /* zero cave in __TEXT */
static void sep_lab_apply_phase2(AppleSEPLabState *s, gsize image_size)
{
    uint8_t *kram;
    uint32_t retab = 0xd65f0fffu;
    uint32_t ret_plain = 0xd65f03c0u;
    uint32_t b_tramp, b_exit;
    uint32_t tramp[12];
    size_t tramp_words, tramp_bytes;
    uint32_t exit_va;
    uint32_t bl_imm;
    int32_t off;
    uint64_t fo;
    const char *wake_env = getenv("SEP_PHASE2_WAKE");
    bool wake = wake_env && *wake_env && strcmp(wake_env, "0") != 0;

    if (!s->sep_phase2) {
        return;
    }
    if (!s->seprom) {
        error_report("SEP lab: sep-phase2=on requires seprom=on; ignored");
        s->sep_phase2 = false;
        return;
    }
    kram = memory_region_get_ram_ptr(&s->kram);

    /* trampoline: save LR, bl start-all, [optional: set [0x133fbb]=1], restore, retab */
    off = (int32_t)SEP_EP_START_ALL - (int32_t)(SEP_EP_TRAMP + 12);
    bl_imm = 0x94000000u | (((uint32_t)(off >> 2)) & 0x03ffffffu);
    tramp[0] = 0xa9bf7bfdu; /* stp x29, x30, [sp, #-0x10]! */
    tramp[1] = 0x910003fdu; /* mov x29, sp */
    tramp[2] = 0xaa1f03e0u; /* mov x0, xzr: local start-all call, not IPC */
    tramp[3] = bl_imm;
    if (wake) {
        tramp[4] = 0x90000088u; /* adrp x8, 0x133000 (from PC 0x123010) */
        tramp[5] = 0x52800029u; /* mov w9, #1 */
        tramp[6] = 0x393eed09u; /* strb w9, [x8, #0xfbb] */
        tramp[7] = 0xa8c17bfdu; /* ldp x29, x30, [sp], #0x10 */
        tramp[8] = retab;
        tramp_words = 9;
    } else {
        tramp[4] = 0xa8c17bfdu; /* ldp x29, x30, [sp], #0x10 */
        tramp[5] = retab;
        tramp_words = 6;
    }
    /*
     * Exit stub for 0x118524: when called from trampoline (x0 == 0), plain ret
     * (AUTIBSP already ran at 0x118514); when called later by sks RPC
     * (0x64, 0x4047) with msg_ctx x0 != 0, branch to original IPC reply 0x11ff2c.
     */
    exit_va = SEP_EP_TRAMP + (uint32_t)(tramp_words * sizeof(uint32_t));
    tramp[tramp_words + 0] = 0xb4000040u; /* cbz x0, .+8 */
    off = (int32_t)SEP_EP_IPC_REPLY - (int32_t)(exit_va + 4);
    tramp[tramp_words + 1] = 0x14000000u | (((uint32_t)(off >> 2)) & 0x03ffffffu);
    tramp[tramp_words + 2] = ret_plain;
    tramp_bytes = (tramp_words + 3) * sizeof(uint32_t);

    fo = SEP_EP_FO(SEP_EP_TRAMP);
    if (fo + tramp_bytes > image_size) {
        error_report("SEP lab: sep-phase2 trampoline OOB");
        return;
    }
    memcpy(kram + fo, tramp, tramp_bytes);

    /* start-all epilogue: reply branch → b exit_va */
    off = (int32_t)exit_va - (int32_t)SEP_EP_START_EXIT;
    b_exit = 0x14000000u | (((uint32_t)(off >> 2)) & 0x03ffffffu);
    fo = SEP_EP_FO(SEP_EP_START_EXIT);
    if (fo + 4 > image_size) {
        error_report("SEP lab: sep-phase2 start-all exit OOB");
        return;
    }
    memcpy(kram + fo, &b_exit, 4);

    /* create-fn retab → b trampoline */
    off = (int32_t)SEP_EP_TRAMP - (int32_t)SEP_EP_CREATE_RET;
    b_tramp = 0x14000000u | (((uint32_t)(off >> 2)) & 0x03ffffffu);
    fo = SEP_EP_FO(SEP_EP_CREATE_RET);
    if (fo + 4 > image_size) {
        error_report("SEP lab: sep-phase2 create ret OOB");
        return;
    }
    memcpy(kram + fo, &b_tramp, 4);

    error_report("SEP lab: sep-phase2 on (create→start-all%s; AKF IRQ 0x80 path)",
                 wake ? "+wake" : "");
}

/* Default-off, env-gated in-memory image patcher (SEP_PATCH). Patches ONLY the
 * kram copy of the loaded image (never the file on disk) so documented debug
 * assertions can be neutered to see how far sepOS boots. Format:
 *   SEP_PATCH="0x10350=0x14000005,0xVA=0xWORD,..."  (32-bit LE words)
 * A VA may be a raw file offset (0x10350) or a high kernel VA
 * (0xffffffff00010350); both resolve to the same kram offset. */
static void sep_lab_apply_patches(AppleSEPLabState *s, gsize image_size)
{
    const char *spec = getenv("SEP_PATCH");
    uint8_t *kram;
    g_auto(GStrv) items = NULL;
    int i;

    if (!s->seprom || !spec || !*spec) {
        return;
    }
    kram = memory_region_get_ram_ptr(&s->kram);
    items = g_strsplit(spec, ",", -1);
    for (i = 0; items[i]; i++) {
        char *eq = strchr(items[i], '=');
        uint64_t va, off;
        uint64_t word64;
        if (!eq) {
            continue;
        }
        *eq = '\0';
        if (qemu_strtou64(g_strstrip(items[i]), NULL, 0, &va) < 0 ||
            qemu_strtou64(g_strstrip(eq + 1), NULL, 0, &word64) < 0) {
            error_report("SEP_PATCH: bad entry '%s'", items[i]);
            continue;
        }
        off = (va >= SEP_KRAM_BASE) ? (va - SEP_KRAM_BASE) : (va & 0xffffffffULL);
        if (off + 4 > image_size) {
            error_report("SEP_PATCH: offset 0x%" PRIx64 " out of image", off);
            continue;
        }
        {
            uint32_t word = (uint32_t)word64;
            memcpy(kram + off, &word, 4);
            error_report("SEP_PATCH: [0x%" PRIx64 "] = 0x%08x", off, word);
        }
    }
}

/* Development-only service initialization compatibility. These two AKF opens
 * otherwise leave xART and scrd waiting forever for a server that never starts.
 * Return success without changing any on-disk bytes. */
static void sep_lab_apply_init_compat(AppleSEPLabState *s, gsize image_size)
{
    static const struct {
        uint64_t off;
        uint32_t word;
    } patches[] = {
        { 0xe94b0u, 0xd28001e0u }, /* scrd: AKF open at runtime 0x1214b0 */
        { 0xe94d0u, 0xd28001e0u }, /* scrd: EMBX open at runtime 0x1214d0 */
        { 0xe94f0u, 0xd28001e0u }, /* scrd: GPIO open at runtime 0x1214f0 */
        { 0xe952cu, 0xd28001e0u }, /* scrd: xART open at runtime 0x12152c */
        { 0xe9560u, 0xd2800000u }, /* scrd: xART RPC at runtime 0x121560 */
    };
    uint8_t *kram;
    unsigned i;

    if (!getenv("SEP_INIT_COMPAT")) {
        return;
    }
    kram = memory_region_get_ram_ptr(&s->kram);
    for (i = 0; i < ARRAY_SIZE(patches); i++) {
        if (patches[i].off + 4 > image_size) {
            error_report("SEP_INIT_COMPAT: offset 0x%" PRIx64 " out of image",
                         patches[i].off);
            continue;
        }
        memcpy(kram + patches[i].off, &patches[i].word, 4);
        error_report("SEP_INIT_COMPAT: [0x%" PRIx64 "] = 0x%08x",
                     patches[i].off, patches[i].word);
    }
}

static void sep_lab_init(MachineState *machine)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(machine);
    g_autofree gchar *image = NULL;
    g_autoptr(GError) file_error = NULL;
    gsize image_size = 0;
    int64_t file_size;
    MemoryRegion *system_memory = get_system_memory();

    if (s->seprom) {
        s->discover = true; /* seprom is a superset of discover */
    }
    if (!tcg_enabled()) {
        error_report("SEP lab requires TCG; host virtualization is not a SEP model");
        exit(EXIT_FAILURE);
    }
    if (!machine->firmware) {
        error_report("SEP lab requires -bios <raw-plaintext-image>");
        exit(EXIT_FAILURE);
    }
    file_size = get_image_size(machine->firmware);
    if (file_size <= 0 || file_size > machine->ram_size ||
        (file_size & 3) || (s->entry & 3) || s->entry >= file_size) {
        error_report("SEP lab: image must be nonempty, 4-byte aligned, fit "
                     "the lab RAM, and contain the aligned entry point");
        exit(EXIT_FAILURE);
    }
    if (!g_file_get_contents(machine->firmware, &image, &image_size,
                             &file_error)) {
        error_report("SEP lab: cannot read firmware: %s", file_error->message);
        exit(EXIT_FAILURE);
    }
    if (image_size != file_size ||
        memmem(image, MIN(image_size, 32), "IM4P", 4) ||
        memmem(image, MIN(image_size, 32), "IMG4", 4)) {
        error_report("SEP lab accepts a raw image, not IMG4/IM4P containers");
        exit(EXIT_FAILURE);
    }
    if (image_size >= 4 &&
        (!memcmp(image, "\xcf\xfa\xed\xfe", 4) ||
         !memcmp(image, "\xce\xfa\xed\xfe", 4))) {
        error_report("SEP lab: a Mach-O application requires its own loader; "
                     "it is not a raw boot image");
        exit(EXIT_FAILURE);
    }
    s->trace = stderr;
    if (s->trace_path) {
        s->trace = fopen(s->trace_path, "w");
        if (!s->trace) {
            error_report("SEP lab: cannot open trace '%s': %s",
                         s->trace_path, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    /* RAM at zero is a lab choice, not a claim about T8140's private map. */
    memory_region_add_subregion(system_memory, 0, machine->ram);
    memory_region_init(&s->private_memory, OBJECT(s), "sep-private", UINT64_MAX);
    address_space_init(&s->private_as, &s->private_memory, "sep-private-as");
    s->unknown = (SEPLabRegion) {
        .lab = s, .domain = "sep-private", .name = "unimplemented", .base = 0,
    };
    memory_region_init_io(&s->unknown.mr, OBJECT(s), &sep_lab_ops, &s->unknown,
                          "sep-private-unimplemented", UINT64_MAX);
    memory_region_add_subregion_overlap(&s->private_memory, 0,
                                        &s->unknown.mr, -100);
    memory_region_init_alias(&s->private_ram, OBJECT(s), "sep-private-ram",
                             machine->ram, 0, machine->ram_size);
    memory_region_add_subregion_overlap(&s->private_memory, 0,
                                        &s->private_ram, 0);

    /* Discovery mode backs the SEP SRAM with real RAM so the stack at
     * 0x2a0220000 works and the kernel runs far enough to touch its KIC and
     * mailbox (whose addresses this trace is meant to reveal). Off by default. */
    if (s->discover) {
        /* owner NULL: a MachineState is not a DeviceState, and a non-NULL
         * non-device owner crashes memory_region_init_ram via qdev_get_dev_path. */
        memory_region_init_ram(&s->sram, NULL, "sep-sram", SEP_SRAM_SIZE,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_SRAM_BASE,
                                            &s->sram, 0);
    }
    if (s->seprom) {
        /* SEP DRAM the kernel builds its page tables in, plus the two
         * memory-config register pages backed as RAM so gdb can poke the
         * handoff values and iterate. */
        memory_region_init_ram(&s->carveout, NULL, "sep-carveout",
                               SEP_CARVEOUT_SIZE, &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory,
                                            SEP_CARVEOUT_BASE, &s->carveout, 0);
        /*
         * cfg0800 was 64 KiB RAM for handoff pokes. First app maps 0x80000
         * at the same PA as PMGR (SSEASMBT). One buffer-backed IO region.
         */
        s->pmgr_regs = g_new0(uint32_t, SEP_PMGR_SIZE / 4);
        memory_region_init_io(&s->cfg0800, NULL, &sep_pmgr_ops, s,
                              "sep-cfg0800", SEP_PMGR_SIZE);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_PMGR_PA,
                                            &s->cfg0800, 0);
        /* EXCL sentinel window (AKPLCXE); not a mailbox. */
        memory_region_init_ram(&s->excl, NULL, "sep-excl", SEP_EXCL_SIZE,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_EXCL_PA,
                                            &s->excl, 0);
        /* AKPESAB only — must NOT cover 0x2a0a00000 (early status is W1C/0). */
        memory_region_init_ram(&s->akp_sab, NULL, "sep-akp-sab", 0x4000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2a0940000ULL,
                                            &s->akp_sab, 0);
        memory_region_init_ram(&s->akp_mmt, NULL, "sep-akp-mmt", 0x4000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2a0a08000ULL,
                                            &s->akp_mmt, 0);
        /* Ends at 0x2a0c40000 — must not shadow cfg0c40. */
        memory_region_init_ram(&s->akp_hi, NULL, "sep-akp-hi", 0x140000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2a0b00000ULL,
                                            &s->akp_hi, 0);
        /* SSEAESAB ('AESS'/'BASE') overlay on top of akp_hi RAM. */
        memory_region_init_io(&s->aess_mr, NULL, &sep_aess_ops, s,
                              "sep-aess-regs", SEP_AESS_SIZE);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_AESS_PA,
                                            &s->aess_mr, 10);
        /* TRNG REGS overlay (W1C +0x10) on top of akp_hi RAM. */
        memory_region_init_io(&s->trng_mr, NULL, &sep_trng_ops, s,
                              "sep-trng-regs", SEP_TRNG_SIZE);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_TRNG_PA,
                                            &s->trng_mr, 10);
        /* KEY.FCFG +0x8000 over plat RAM (prio above plat). */
        memory_region_init_io(&s->key_fcfg_mr, NULL, &sep_key_fcfg_ops, s,
                              "sep-key-fcfg", 4);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_KEY_FCFG_PA,
                                            &s->key_fcfg_mr, 10);
        /* Platform pages 0x2a0d80000..0x2a0e80000 (sentinels + timer tail). */
        memory_region_init_ram(&s->plat, NULL, "sep-plat", 0x100000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2a0d80000ULL,
                                            &s->plat, 0);
        /*
         * BASEI2C / BASEGPIO sit just past plat. Latch writes so dxio_async's
         * command word at GPIO +0xc is visible to the following read.
         */
        s->i2c_regs = g_new0(uint32_t, SEP_IO_BLK_SIZE / 4);
        s->gpio_regs = g_new0(uint32_t, SEP_IO_BLK_SIZE / 4);
        memory_region_init_io(&s->i2c_mr, NULL, &sep_io_blk_ops, s->i2c_regs,
                              "sep-i2c", SEP_IO_BLK_SIZE);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_I2C_PA,
                                            &s->i2c_mr, 10);
        memory_region_init_io(&s->gpio_mr, NULL, &sep_io_blk_ops, s->gpio_regs,
                              "sep-gpio", SEP_IO_BLK_SIZE);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_GPIO_PA,
                                            &s->gpio_mr, 10);
        /* Loader __phys_range: KIC 0x2a0c40000 / 0x40000 (flags 4). */
        memory_region_init_ram(&s->cfg0c40, NULL, "sep-cfg0c40", 0x40000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2a0c40000ULL,
                                            &s->cfg0c40, 1);
        /* SEP security-fuse shadow. sepOS's secfuse init (image 0x8d80) maps
         * PA 0x2e42c8000 (16 KiB) and asserts (secfuse.c:52, panic thunk
         * 0xa23c) that fuse words [0] and [1] each equal one of two hardcoded
         * sentinels built at image 0x8d38: 0xa55ac33c or 0xa050c030. Back it as
         * RAM and seed the sentinels so sepOS proceeds; remaining fuse fields
         * are discovered by iteration (gdb pokes this RAM). */
        /*
         * XPRT window 0x2e42c0000/0x30000: MISC @+0x4000, FUSE @+0x8000,
         * through AKPUCES/PMSC @+0x1c000 (peer phys_range).
         */
        memory_region_init_ram(&s->fuse, NULL, "sep-fuse", 0x30000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2e42c0000ULL,
                                            &s->fuse, 0);
        {
            uint8_t *xprt = memory_region_get_ram_ptr(&s->fuse);
            uint32_t *fz = (uint32_t *)(xprt + 0x8000);

            *(uint32_t *)(xprt + 0x4000) = 0x32b3; /* XPRT.MISC */
            fz[0] = 0xa55ac33c;
            fz[1] = 0xa55ac33c;
        }
        /* Broad SEP MMIO swath backed as RAM so the platform register blocks
         * sepOS's sep64 init reads (e.g. the memory-config block at 0x2a2400000,
         * mapped +0x4810.. returning a region base/size with a 0xfe type tag)
         * can be seeded and iterated with gdb without a rebuild per register. */
        memory_region_init_ram(&s->sepmmio, NULL, "sep-mmio", 0x1000000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2a2000000ULL,
                                            &s->sepmmio, 0);
        memory_region_init_ram(&s->kram, NULL, "sep-kram", SEP_KRAM_SIZE,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_KRAM_BASE,
                                            &s->kram, 0);
        /* Run sepOS from the SEP RAM carveout, as SEPROM loads it: the kernel's
         * own map points VA 0xffffffff00000000 -> PA 0x1e40000000, so the image
         * must be there (not PA 0). The image's 0x24000..end is zero BSS, which
         * is exactly where the page-table pool (0x1e40024000) is allocated, so
         * the tables overwrite only zero BSS. Reset directly into the carveout. */
        memcpy(memory_region_get_ram_ptr(&s->kram), image, image_size);
        s->entry = SEP_KRAM_BASE;
        sep_lab_apply_patches(s, image_size);
        sep_lab_apply_phase2(s, image_size);
        sep_lab_apply_init_compat(s, image_size);
        /* Handoff memory region the sep64 region encode points at. The real
         * SEPROM maps SEP DRAM here and writes the tagged record directory the
         * kernel parses at image 0x8f70; back it as RAM so the loader
         * (sep_lab_seed_handoff) can lay that blob down. */
        memory_region_init_ram(&s->region, NULL, "sep-region", SEP_REGION_SIZE,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_REGION_BASE,
                                            &s->region, 0);
        if (getenv("SEP_TRAP_74430")) {
            memset(s->trapbuf, 0, sizeof(s->trapbuf)); /* pool starts zeroed */
            memory_region_init_io(&s->trap, OBJECT(s), &sep_trap_ops, s,
                                  "sep-trap-74430", sizeof(s->trapbuf));
            memory_region_add_subregion_overlap(&s->private_memory, SEP_TRAP_PA,
                                                &s->trap, 1);
            error_report("SEP lab DEBUG: trap over 0x%llx active",
                         (unsigned long long)SEP_TRAP_PA);
        }
    }

    /* AP regions are not silently reused as the SEP's private MMIO map. */
    for (unsigned i = 0; i < ARRAY_SIZE(d47_ap_regions); i++) {
        SEPLabRegion *r = &s->ap[i];
        r->lab = s;
        r->domain = "ap";
        r->name = d47_ap_regions[i].name;
        r->base = d47_ap_regions[i].address;
        memory_region_init_io(&r->mr, OBJECT(s), &sep_lab_ops, r, r->name,
                              d47_ap_regions[i].size);
        memory_region_add_subregion(system_memory, r->base, &r->mr);
    }

    s->cpu = ARM_CPU(object_new(machine->cpu_type));
    object_property_set_bool(OBJECT(s->cpu), "has_el3", false, &error_fatal);
    object_property_set_bool(OBJECT(s->cpu), "has_el2", false, &error_fatal);
    /* Discovery mode installs the SEP's IMPDEF system registers (boot role,
     * ready bit, the crn=15 cluster) so sepOS gets past its first Apple mrs
     * at 0xa00 and runs its real platform init -- exactly as modern-sep-core
     * does. Without it the generic core parks at 0xa00 and reveals nothing. */
    if (s->discover) {
        object_property_set_bool(OBJECT(s->cpu), "apple-modern-sep", true,
                                 &error_fatal);
        /* Apple's SEP runs on a 24 MHz timebase. sepOS's timer init (image
         * 0x8e58) reads CNTFRQ_EL0 and panics (timer.c:19, thunk 0xa24c) unless
         * it is exactly 24000000; the platform/SEPROM programs it before sepOS
         * runs, so model it on the lab CPU. */
        object_property_set_int(OBJECT(s->cpu), "cntfrq", 24000000,
                                &error_fatal);
    }
    object_property_set_link(OBJECT(s->cpu), "memory",
                             OBJECT(&s->private_memory), &error_fatal);
    qdev_realize(DEVICE(s->cpu), NULL, &error_fatal);
    /* The SEP cpu's IRQ input, so a mailbox doorbell (or the x-irq test trigger)
     * can wake sepOS from its WFE mailbox-wait. */
    s->sep_irq = qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_IRQ);
    sep_lab_init_timer(s);
    sep_lab_init_trng_irq(s);
    sep_lab_init_inject(s);
    sep_lab_init_stack_fix(s);
    sep_lab_exclog_init(s);
    if (s->sep_phase2) {
        const char *synth_env = getenv("SEP_SYNTH_SERVE");

        s->synth_serve = synth_env && *synth_env && strcmp(synth_env, "0");
        {
            const char *e0_env = getenv("SEP_SYNTH_E0");

            s->synth_e0 = e0_env && *e0_env && strcmp(e0_env, "0");
        }
        arm_register_pre_el_change_hook(s->cpu, sep_lab_sars_ipc_pre_hook, s);
        arm_register_el_change_hook(s->cpu, sep_lab_sars_ipc_post_hook, s);
    }
    qemu_register_reset(sep_lab_reset, s);
    rom_add_blob_fixed("sep-lab.raw-image", image, image_size, 0);
    error_setg(&s->migration_blocker,
               "SEP lab migration/snapshot semantics are not implemented");
    if (migrate_add_blocker(&s->migration_blocker, &error_fatal) < 0) {
        exit(EXIT_FAILURE);
    }

    error_report("SEP lab: generic AArch64/EL1, %" PRIu64
                 " bytes of lab RAM; D47 AP metadata only. "
                 "No T8140 CPU, ASC-v6 protocol, secure boot, or SKS "
                 "compatibility is claimed.",
                 (uint64_t)machine->ram_size);
}

static char *sep_lab_get_trace(Object *obj, Error **errp)
{
    const char *path = APPLE_SEP_LAB(obj)->trace_path;
    return g_strdup(path ? path : "");
}

static void sep_lab_set_trace(Object *obj, const char *value, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);
    g_free(s->trace_path);
    s->trace_path = g_strdup(value);
}

static char *sep_lab_get_entry(Object *obj, Error **errp)
{
    return g_strdup_printf("0x%" PRIx64, APPLE_SEP_LAB(obj)->entry);
}

static void sep_lab_set_entry(Object *obj, const char *value, Error **errp)
{
    uint64_t entry;
    if (qemu_strtou64(value, NULL, 0, &entry) < 0 || (entry & 3)) {
        error_setg(errp, "entry must be a non-negative, 4-byte aligned integer");
        return;
    }
    APPLE_SEP_LAB(obj)->entry = entry;
}

static bool sep_lab_get_discover(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->discover;
}

static void sep_lab_set_discover(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->discover = value;
}

/* Host-only IRQ trigger (QMP qom-set x-irq=1/0): raise/lower the SEP cpu's IRQ
 * line to wake sepOS from its WFE mailbox-wait. NOT a SEP wire operation; a
 * reconnaissance aid until the real ASC-v6 mailbox drives this line. */
static char *sep_lab_get_irq(Object *obj, Error **errp)
{
    return g_strdup("");
}

static void sep_lab_set_irq(Object *obj, const char *value, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);
    if (!s->sep_irq) {
        error_setg(errp, "x-irq is available only after machine init");
        return;
    }
    qemu_set_irq(s->sep_irq, value && value[0] && value[0] != '0');
}


/* ---- sep-inject: ASC-v6 IOP mailbox player (default off) ---- */

static void sep_lab_update_irq(AppleSEPLabState *s)
{
    bool raise = s->t_pending || s->trng_pending || s->ext_irq_edge ||
                 (s->sep_inject && s->mbox_pending);

    if (s->sep_irq) {
        qemu_set_irq(s->sep_irq, raise);
    }
}

static uint32_t sep_inject_a2i_ctrl_read(AppleSEPLabState *s)
{
    uint32_t v = s->a2i_ctrl_en & SEP_MBOX_CTRL_EN;

    if (s->a2i_count == 0) {
        v |= SEP_MBOX_CTRL_EMPTY;
    } else {
        uint32_t c = s->a2i_count > 15 ? 15 : s->a2i_count;
        v |= c << SEP_MBOX_CTRL_COUNT_SHIFT;
    }
    return v;
}

static uint32_t sep_inject_i2a_ctrl_read(AppleSEPLabState *s)
{
    return (s->i2a_ctrl_en & SEP_MBOX_CTRL_EN) | SEP_MBOX_CTRL_EMPTY;
}

static void sep_inject_raise_doorbell(AppleSEPLabState *s)
{
    if (!s->sep_inject || s->a2i_count == 0) {
        return;
    }
    /* a7iop: IOP_NONEMPTY line stays low while the bit is masked. */
    if (s->mbox_int_mask & SEP_MBOX_IOP_NONEMPTY) {
        error_report("SEP inject: doorbell suppressed (IOP_NONEMPTY masked "
                     "int_mask=0x%x a2i=%u)", s->mbox_int_mask, s->a2i_count);
        return;
    }
    s->mbox_pending = true;
    sep_lab_update_irq(s);
    error_report("SEP inject: doorbell (a2i=%u KIC=0x%x)",
                 s->a2i_count, s->mbox_kic_event);
}

static bool sep_inject_enqueue(AppleSEPLabState *s, const uint8_t msg[16],
                               bool doorbell)
{
    if (s->a2i_count >= SEP_INJECT_QDEPTH) {
        error_report("SEP inject: A2I FIFO full");
        return false;
    }
    memcpy(s->a2i_q[s->a2i_tail], msg, 16);
    s->a2i_tail = (s->a2i_tail + 1) % SEP_INJECT_QDEPTH;
    s->a2i_count++;
    s->inject_enqueues++;
    error_report("SEP inject: A2I ep=%u tag=%u op=%u param=%u data=0x%08x%s",
                 msg[0], msg[1], msg[2], msg[3], ldl_le_p(msg + 4),
                 doorbell ? " +doorbell" : "");
    if (doorbell) {
        sep_inject_raise_doorbell(s);
    }
    return true;
}

static void sep_inject_seed_boot_descriptor(AppleSEPLabState *s)
{
    uint8_t boot[16];

    memset(boot, 0, sizeof(boot));
    stl_le_p(boot + 0, 0x040000fe);
    stl_le_p(boot + 4, 0x10000000);
    sep_inject_enqueue(s, boot, false);
}

static void sep_inject_reset_state(AppleSEPLabState *s)
{
    s->a2i_head = s->a2i_tail = s->a2i_count = 0;
    s->outbox_count = 0;
    s->mbox_pending = false;
    if (!s->mbox_kic_event) {
        s->mbox_kic_event = SEP_KIC_MBOX_EVENT;
    }
    /* Match a7iop: int_mask defaults fully unmasked so NONEMPTY can fire.
     * Kernel later SET 0x55551111; AKF CLR 0x10 to unmask NONEMPTY again. */
    s->mbox_int_mask = 0;
    s->a2i_ctrl_en = SEP_MBOX_CTRL_EN;
    s->i2a_ctrl_en = SEP_MBOX_CTRL_EN;
    memset(s->a2i_send_scratch, 0, sizeof(s->a2i_send_scratch));
    memset(s->a2i_recv_scratch, 0, sizeof(s->a2i_recv_scratch));
    memset(s->i2a_send_scratch, 0, sizeof(s->i2a_send_scratch));
    memset(s->i2a_recv_scratch, 0, sizeof(s->i2a_recv_scratch));
    sep_inject_seed_boot_descriptor(s);
}

static void sep_inject_capture_outbox(AppleSEPLabState *s, const uint8_t msg[16])
{
    unsigned slot = s->outbox_count < SEP_INJECT_OUTLOG ? s->outbox_count
                                                       : SEP_INJECT_OUTLOG - 1;

    memcpy(s->outbox_log[slot], msg, 16);
    if (s->outbox_count < SEP_INJECT_OUTLOG) {
        s->outbox_count++;
    }
    s->outbox_posts++;
    error_report("SEP inject: I2A outbox ep=%u tag=%u op=%u param=%u data=0x%08x "
                 "(post #%" PRIu64 ")",
                 msg[0], msg[1], msg[2], msg[3], ldl_le_p(msg + 4),
                 s->outbox_posts);
}

static uint64_t sep_mbox_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;
    uint64_t ret = 0;

    switch (off) {
    case 0x00:
    case 0x08:
        /* ASC-v6 mailbox: INT_MASK_SET (+0x4100) / INT_MASK_CLR (+0x4108).
         * Read returns the live mask (kernel SET 0x55551111 is visible). */
        return s->mbox_int_mask;
    case 0x10:
        return sep_inject_a2i_ctrl_read(s);
    case 0x14:
        return sep_inject_i2a_ctrl_read(s);
    case 0x710:
        if (s->a2i_count == 0) {
            memset(s->a2i_recv_scratch, 0, 16);
        } else {
            memcpy(s->a2i_recv_scratch, s->a2i_q[s->a2i_head], 16);
            s->a2i_head = (s->a2i_head + 1) % SEP_INJECT_QDEPTH;
            s->a2i_count--;
            s->inject_dequeues++;
            error_report("SEP inject: SEP popped A2I ep=%u tag=%u op=%u (left=%u)",
                         s->a2i_recv_scratch[0], s->a2i_recv_scratch[1],
                         s->a2i_recv_scratch[2], s->a2i_count);
        }
        /* fall through */
    case 0x714:
    case 0x718:
    case 0x71c:
        memcpy(&ret, s->a2i_recv_scratch + (off - 0x710), size);
        return ret;
    case 0x730:
    case 0x734:
    case 0x738:
    case 0x73c:
        memcpy(&ret, s->i2a_recv_scratch + (off - 0x730), size);
        return ret;
    default:
        return 0;
    }
}

static void sep_mbox_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    AppleSEPLabState *s = opaque;

    switch (off) {
    case 0x00:
        /* INT_MASK_SET (a7iop REG_INT_MASK_SET): OR bits into the mask. */
        s->mbox_int_mask |= (uint32_t)val;
        if (s->mbox_int_mask & SEP_MBOX_IOP_NONEMPTY) {
            s->mbox_pending = false;
            sep_lab_update_irq(s);
        }
        error_report("SEP inject: INT_MASK_SET |= 0x%x → mask 0x%x",
                     (uint32_t)val, s->mbox_int_mask);
        break;
    case 0x08:
        /* INT_MASK_CLR: AND-NOT. AKF writes 0x10 to unmask IOP_NONEMPTY. */
        s->mbox_int_mask &= ~(uint32_t)val;
        error_report("SEP inject: INT_MASK_CLR &= ~0x%x → mask 0x%x",
                     (uint32_t)val, s->mbox_int_mask);
        if ((val & SEP_MBOX_IOP_NONEMPTY) && s->a2i_count) {
            sep_inject_raise_doorbell(s);
        }
        break;
    case 0x10:
        s->a2i_ctrl_en = (uint32_t)val & SEP_MBOX_CTRL_EN;
        break;
    case 0x14:
        s->i2a_ctrl_en = (uint32_t)val & SEP_MBOX_CTRL_EN;
        break;
    case 0x700:
    case 0x704:
    case 0x708:
    case 0x70c:
        memcpy(s->a2i_send_scratch + (off - 0x700), &val, size);
        break;
    case 0x720:
    case 0x724:
    case 0x728:
    case 0x72c:
        memcpy(s->i2a_send_scratch + (off - 0x720), &val, size);
        if (off + size >= 0x730) {
            sep_inject_capture_outbox(s, s->i2a_send_scratch);
            memset(s->i2a_send_scratch, 0, 16);
        }
        break;
    default:
        error_report("SEP inject: unmodelled mbox write +0x%" HWADDR_PRIx
                     " = 0x%" PRIx64, SEP_ASC_MBOX_OFF + off, val);
        break;
    }
}

static const MemoryRegionOps sep_mbox_ops = {
    .read = sep_mbox_read,
    .write = sep_mbox_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 8 },
};

static void sep_inject_pack(uint8_t out[16], uint8_t ep, uint8_t tag,
                            uint8_t op, uint8_t param, uint32_t data)
{
    memset(out, 0, 16);
    out[0] = ep;
    out[1] = tag;
    out[2] = op;
    out[3] = param;
    stl_le_p(out + 4, data);
}

static bool sep_inject_named(AppleSEPLabState *s, const char *name, bool doorbell)
{
    uint8_t msg[16];

    if (!strcmp(name, "ping")) {
        sep_inject_pack(msg, 0xff, 0, 1, 0, 0);
    } else if (!strcmp(name, "status")) {
        sep_inject_pack(msg, 0xff, 0, 2, 0, 0);
    } else if (!strcmp(name, "alive")) {
        sep_inject_pack(msg, 0, 0, 13, 0, 0);
    } else if (!strcmp(name, "epmap")) {
        sep_inject_pack(msg, 0xfd, 0, 0, 0, 0);
    } else if (!strcmp(name, "sksopen")) {
        sep_inject_pack(msg, 18, 0, 0, 0, 0);
    /*
     * sepOS runtime control endpoint (ep0, AppleSEPControl). Each request is
     * answered by an ep0 op=1 ACK (verified sep-phase2). ep0xff/0xfd are the
     * SEPROM boot and SEP->AP discovery endpoints: popped but never answered
     * once sepOS runs. OOL addr/size data are lab placeholders (no DART).
     */
    } else if (!strcmp(name, "ctrl-nop")) {
        sep_inject_pack(msg, 0, 0, 0, 0, 0);
    } else if (!strcmp(name, "ool-in-addr")) {
        sep_inject_pack(msg, 0, 0, 2, 0, 0x1000);
    } else if (!strcmp(name, "ool-out-addr")) {
        sep_inject_pack(msg, 0, 0, 3, 0, 0x2000);
    } else if (!strcmp(name, "ool-in-size")) {
        sep_inject_pack(msg, 0, 0, 4, 0, 1);
    } else if (!strcmp(name, "ool-out-size")) {
        sep_inject_pack(msg, 0, 0, 5, 0, 1);
    } else if (!strcmp(name, "secmode")) {
        sep_inject_pack(msg, 0, 0, 20, 0, 0);
    } else if (!strcmp(name, "selftest")) {
        sep_inject_pack(msg, 0, 0, 24, 0, 0);
    } else if (!strcmp(name, "ctrl-handshake")) {
        /* AP reply to the cntl advertise/expose + op13/op41 announce. */
        static const char *const seq[] = {
            "ctrl-nop", "ool-in-addr", "ool-out-addr",
            "ool-in-size", "ool-out-size",
        };
        for (size_t i = 0; i < ARRAY_SIZE(seq); i++) {
            if (!sep_inject_named(s, seq[i], doorbell)) {
                return false;
            }
        }
        return true;
    } else {
        return false;
    }
    return sep_inject_enqueue(s, msg, doorbell);
}

static int sep_inject_parse_one(AppleSEPLabState *s, const char *tok, Error **errp)
{
    uint8_t msg[16];
    int ep = 0, tag = 0, op = 0, param = 0;
    unsigned data = 0;
    int n;

    while (*tok == ' ' || *tok == '\t') {
        tok++;
    }
    if (!*tok) {
        return 0;
    }
    if (sep_inject_named(s, tok, true)) {
        return 0;
    }
    if (!strncmp(tok, "hex:", 4)) {
        const char *p = tok + 4;
        for (int i = 0; i < 16; i++) {
            unsigned v;
            if (sscanf(p + 2 * i, "%2x", &v) != 1) {
                error_setg(errp, "x-inject hex: needs 32 hex digits");
                return -1;
            }
            msg[i] = (uint8_t)v;
        }
        return sep_inject_enqueue(s, msg, true) ? 0 : -1;
    }
    n = sscanf(tok, "%i,%i,%i,%i,%i", &ep, &tag, &op, &param, &data);
    if (n < 3) {
        error_setg(errp,
                   "x-inject: ping|status|alive|epmap|sksopen|ctrl-nop|"
                   "ool-in-addr|ool-out-addr|ool-in-size|ool-out-size|"
                   "secmode|selftest|ctrl-handshake or "
                   "ep,tag,op[,param[,data]] or hex:<32 hex digits>");
        return -1;
    }
    if (n < 4) {
        param = 0;
    }
    if (n < 5) {
        data = 0;
    }
    sep_inject_pack(msg, (uint8_t)ep, (uint8_t)tag, (uint8_t)op,
                    (uint8_t)param, (uint32_t)data);
    return sep_inject_enqueue(s, msg, true) ? 0 : -1;
}

static char *sep_lab_get_inject(Object *obj, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);

    return g_strdup_printf("enqueues=%" PRIu64 " dequeues=%" PRIu64
                           " outbox=%" PRIu64 " a2i=%u pending=%d",
                           s->inject_enqueues, s->inject_dequeues,
                           s->outbox_posts, s->a2i_count, s->mbox_pending);
}

static void sep_lab_set_inject(Object *obj, const char *value, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);
    g_autofree char *dup = NULL;
    char *save = NULL;
    char *tok;

    if (!s->sep_inject) {
        error_setg(errp, "x-inject needs sep-inject=on");
        return;
    }
    if (!s->sep_irq) {
        error_setg(errp, "x-inject available only after machine init");
        return;
    }
    if (!value || !value[0]) {
        error_setg(errp, "x-inject: empty");
        return;
    }
    dup = g_strdup(value);
    for (tok = strtok_r(dup, ";+", &save); tok;
         tok = strtok_r(NULL, ";+", &save)) {
        if (sep_inject_parse_one(s, tok, errp) < 0) {
            return;
        }
    }
}

static char *sep_lab_get_outbox(Object *obj, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);
    GString *gs = g_string_new(NULL);
    unsigned n = s->outbox_count < SEP_INJECT_OUTLOG ? s->outbox_count
                                                     : SEP_INJECT_OUTLOG;

    for (unsigned i = 0; i < n; i++) {
        const uint8_t *m = s->outbox_log[i];
        g_string_append_printf(gs,
            "%u: ep=%u tag=%u op=%u param=%u data=0x%08x\n",
            i, m[0], m[1], m[2], m[3], ldl_le_p(m + 4));
    }
    if (!n) {
        g_string_append(gs, "(empty)\n");
    }
    return g_string_free(gs, false);
}

static void sep_lab_set_outbox(Object *obj, const char *value, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);

    if (value && (!strcmp(value, "clear") || !strcmp(value, "0"))) {
        s->outbox_count = 0;
        s->outbox_posts = 0;
    }
}

static void sep_timer_update_irq(AppleSEPLabState *s)
{
    sep_lab_update_irq(s);
}

static void sep_timer_fire(void *opaque)
{
    AppleSEPLabState *s = opaque;
    if (!(s->t_ctrl & 1)) {
        return;
    }
    s->t_stat |= 1;
    s->t_pending = true;
    s->t_fires++;
    if (s->t_fires <= 8 || !(s->t_fires % 100)) {
        error_report("SEP timer: fire #%" PRIu64 " (ctrl=0x%x count=0x%x)",
                     s->t_fires, s->t_ctrl, s->t_count);
    }
    if (s->t_fires == 1 && s->exclog_max) {
        sep_lab_exclog_dump_ring(s, "timer fire #1");
    }
    sep_timer_update_irq(s);
}

static void sep_timer_arm(AppleSEPLabState *s)
{
    uint64_t ticks = s->t_count ? s->t_count : 1;
    int64_t ns = muldiv64(ticks, NANOSECONDS_PER_SECOND, SEP_TIMER_HZ);
    timer_mod(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + ns);
}

static uint64_t sep_timer_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;
    switch (off) {
    case 0x00: return s->t_ctrl;
    case 0x08: return s->t_stat;
    case 0x18: return s->t_count;
    case 0x400:
    case 0x410:
        /* Magic words checked by child servers (Antigravity / image). */
        return SEP_SENTINEL;
    default:   return 0;
    }
}

static void sep_timer_write(void *opaque, hwaddr off, uint64_t val,
                            unsigned size)
{
    AppleSEPLabState *s = opaque;
    switch (off) {
    case 0x00:
        s->t_ctrl = val;
        if (val & 1) {
            sep_timer_arm(s);
        } else {
            timer_del(s->timer);
        }
        break;
    case 0x08:
        s->t_stat &= ~(uint32_t)val;
        if (!(s->t_stat & 1)) {
            s->t_pending = false;
            sep_timer_update_irq(s);
        }
        break;
    case 0x18:
        s->t_count = val;
        break;
    default:
        error_report("SEP timer: unmodelled write +0x%" HWADDR_PRIx
                     " = 0x%" PRIx64, off, val);
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

static uint64_t sep_kic_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;
    if (off == 0x18) {          /* KIC +0x818 EVENT (claim) */
        if (s->trng_pending) {
            s->trng_pending = false;
            s->trng_regs[0x14 / 4] &= ~0x8000u; /* go-bit self-clear on claim */
            sep_lab_update_irq(s);
            error_report("SEP TRNG: KIC claim event 0x%x (IRQ 3)",
                         SEP_KIC_TRNG_EVENT);
            return SEP_KIC_TRNG_EVENT;
        }
        if (s->ext_irq_edge) {
            int bit = ctz32(s->ext_irq_edge);
            uint32_t ev = 0x00010000u | bit;

            s->ext_irq_edge &= ~BIT(bit);
            sep_lab_update_irq(s);
            if (s->ext_irq_claims++ < 32) {
                error_report("SEP ASC: KIC claim ext IRQ %d event 0x%x",
                             bit, ev);
            }
            return ev;
        }
        if (s->sep_inject && s->mbox_pending) {
            s->mbox_pending = false;
            sep_lab_update_irq(s);
            error_report("SEP inject: KIC claim mbox event 0x%x",
                         s->mbox_kic_event);
            return s->mbox_kic_event;
        }
        if (s->t_pending) {
            s->t_pending = false;
            s->t_claims++;
            sep_timer_update_irq(s);
            return SEP_KIC_TIMER_EVENT;
        }
        return 0;
    }
    return 0;
}

static void sep_kic_write(void *opaque, hwaddr off, uint64_t val,
                          unsigned size)
{
    error_report("SEP KIC: write +0x%" HWADDR_PRIx " = 0x%" PRIx64,
                 off + 0x800, val);
}

static const MemoryRegionOps sep_kic_ops = {
    .read = sep_kic_read,
    .write = sep_kic_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void sep_lab_run_inject_script(AppleSEPLabState *s)
{
    g_autofree char *dup = NULL;
    char *save = NULL;
    char *tok;
    Error *local = NULL;

    if (!s->inject_script || !s->inject_script[0]) {
        return;
    }
    dup = g_strdup(s->inject_script);
    error_report("SEP inject: running script '%s'", s->inject_script);
    for (tok = strtok_r(dup, ",;+", &save); tok;
         tok = strtok_r(NULL, ",;+", &save)) {
        if (sep_inject_parse_one(s, tok, &local) < 0) {
            error_report_err(local);
            local = NULL;
        }
    }
}


/* ASC +0xa00/+0x1010 probe overlays: see sep_asc_a00_ops. */

static uint64_t sep_asc_a00_read(void *opaque, hwaddr off, unsigned size)
{
    AppleSEPLabState *s = opaque;

    (void)size;
    /* +0xa00 SET and +0xa80 CLR both read back the live ext IRQ mask. */
    if (off == 0x00 || off == 0x80) {
        return s->ext_irq_mask;
    }
    return 0xffffffffu;
}

static void sep_asc_a00_write(void *opaque, hwaddr off, uint64_t val,
                              unsigned size)
{
    AppleSEPLabState *s = opaque;

    (void)size;
    if (off == 0x00) {
        s->ext_irq_mask |= (uint32_t)val;
        s->ext_irq_edge &= ~(uint32_t)val;
        error_report("SEP ASC: ext IRQ MASK_SET |= 0x%x → 0x%x",
                     (uint32_t)val, s->ext_irq_mask);
        sep_lab_eval_trng_irq(s);
        sep_lab_update_irq(s);
    } else if (off == 0x80) {
        uint32_t newly = s->ext_irq_mask & (uint32_t)val;

        s->ext_irq_mask &= ~(uint32_t)val;
        error_report("SEP ASC: ext IRQ MASK_CLR &= ~0x%x → 0x%x",
                     (uint32_t)val, s->ext_irq_mask);
        sep_lab_eval_trng_irq(s);
        if (newly & SEP_EXT_IRQ_PMGR28000) {
            sep_lab_raise_pmgr28000(s);
        }
        if (newly & (SEP_EXT_IRQ_PMGR2C000 | SEP_EXT_IRQ_PMGR2C000_IRQ7)) {
            sep_lab_raise_pmgr2c000(s);
        }
        sep_lab_update_irq(s);
    }
}

static const MemoryRegionOps sep_asc_a00_ops = {
    .read = sep_asc_a00_read,
    .write = sep_asc_a00_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
};

static uint64_t sep_asc_1010_read(void *opaque, hwaddr off, unsigned size)
{
    (void)opaque;
    (void)size;
    (void)off;
    return 0x2; /* bit1 set — probe 0x7c88 tbz #1 */
}

static void sep_asc_1010_write(void *opaque, hwaddr off, uint64_t val,
                               unsigned size)
{
    (void)opaque;
    (void)off;
    (void)val;
    (void)size;
}

static const MemoryRegionOps sep_asc_1010_ops = {
    .read = sep_asc_1010_read,
    .write = sep_asc_1010_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
};


static void sep_lab_init_trng_irq(AppleSEPLabState *s)
{
    if (!s->sep_trng_irq) {
        return;
    }
    if (!s->seprom) {
        error_report("SEP lab: sep-trng-irq=on requires seprom=on; ignored");
        s->sep_trng_irq = false;
        return;
    }
    s->ext_irq_mask = 0xffffffffu;
    s->ext_irq_edge = 0;
    s->pmgr28000_latched = false;
    s->pmgr2c000_latched = false;
    s->trng_pending = false;
    if (!s->sep_timer && !s->sep_inject) {
        memory_region_init_io(&s->kic_mr, NULL, &sep_kic_ops, s,
                              "sep-kic-event", 0x100);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_KIC_EVT_PA,
                                            &s->kic_mr, 20);
        error_report("SEP lab: sep-trng-irq brought up KIC +0x818");
    }
    if (!s->sep_inject) {
        memory_region_init_io(&s->asc_a00_mr, NULL, &sep_asc_a00_ops, s,
                              "sep-asc-a00", 0x100);
        memory_region_add_subregion_overlap(&s->private_memory,
                                            SEP_ASC_PA + 0xa00,
                                            &s->asc_a00_mr, 25);
        memory_region_init_io(&s->asc_1010_mr, NULL, &sep_asc_1010_ops, s,
                              "sep-asc-1010", 0x8);
        memory_region_add_subregion_overlap(&s->private_memory,
                                            SEP_ASC_PA + 0x1010,
                                            &s->asc_1010_mr, 25);
    }
    error_report("SEP lab: sep-trng-irq on (KIC 0x%x → IRQ 3; gate +0xa80 bit3)",
                 SEP_KIC_TRNG_EVENT);
}

static void sep_lab_init_inject(AppleSEPLabState *s)
{
    if (!s->sep_inject) {
        return;
    }
    if (!s->seprom) {
        error_report("SEP lab: sep-inject=on requires seprom=on; ignored");
        s->sep_inject = false;
        return;
    }
    if (!s->sep_timer) {
        memory_region_init_io(&s->kic_mr, NULL, &sep_kic_ops, s,
                              "sep-kic-event", 0x100);
        memory_region_add_subregion_overlap(&s->private_memory, SEP_KIC_EVT_PA,
                                            &s->kic_mr, 20);
        error_report("SEP lab: sep-inject brought up KIC +0x818 (no sep-timer)");
    }
    memory_region_init_io(&s->mbox_mr, NULL, &sep_mbox_ops, s,
                          "sep-asc-mbox", SEP_ASC_MBOX_SIZE);
    memory_region_add_subregion_overlap(&s->private_memory,
                                        SEP_ASC_PA + SEP_ASC_MBOX_OFF,
                                        &s->mbox_mr, 25);
    /* Probe windows for 0x7c88 (prio over sepmmio RAM). */
    memory_region_init_io(&s->asc_a00_mr, NULL, &sep_asc_a00_ops, s,
                          "sep-asc-a00", 0x100);
    memory_region_add_subregion_overlap(&s->private_memory, SEP_ASC_PA + 0xa00,
                                        &s->asc_a00_mr, 25);
    memory_region_init_io(&s->asc_1010_mr, NULL, &sep_asc_1010_ops, s,
                          "sep-asc-1010", 0x8);
    memory_region_add_subregion_overlap(&s->private_memory, SEP_ASC_PA + 0x1010,
                                        &s->asc_1010_mr, 25);
    s->ext_irq_mask = 0xffffffffu;
    s->ext_irq_edge = 0;
    s->pmgr28000_latched = false;
    s->pmgr2c000_latched = false;
    s->trng_pending = false;
    sep_inject_reset_state(s);
    if (s->inject_script && s->inject_script[0]) {
        sep_lab_run_inject_script(s);
    }
    error_report("SEP lab: sep-inject on (ASC IOP mbox 0x%llx+0x%x; "
                 "QOM x-inject / x-outbox; script=%s)",
                 (unsigned long long)SEP_ASC_PA, SEP_ASC_MBOX_OFF,
                 s->inject_script && s->inject_script[0] ? s->inject_script
                                                         : "(none)");
}


/* ---- sep-stack-fix: synthetic EL0 stack Trans_L3 filler (default off) ---- */

static uint64_t sep_lab_ttbr0_l2_pte(AddressSpace *as, uint64_t ttbr0,
                                    uint64_t va, hwaddr *pte_pa_out)
{
    MemTxResult tx;
    uint64_t l1_pa = ttbr0 & ~0xfffULL;
    uint64_t i1 = (va >> 25) & 0x7ff;
    uint64_t i2 = (va >> 14) & 0x7ff;
    uint64_t l1e, l2_pa, l2e;

    l1e = address_space_ldq_le(as, l1_pa + 8 * i1, MEMTXATTRS_UNSPECIFIED, &tx);
    if (tx != MEMTX_OK || (l1e & 0x3) != 0x3) {
        return 0;
    }
    l2_pa = l1e & 0xfffffffff000ULL;
    if (pte_pa_out) {
        *pte_pa_out = l2_pa + 8 * i2;
    }
    l2e = address_space_ldq_le(as, l2_pa + 8 * i2, MEMTXATTRS_UNSPECIFIED, &tx);
    return (tx == MEMTX_OK) ? l2e : 0;
}

static bool sep_lab_fill_one_page(AppleSEPLabState *s, AddressSpace *as,
                                 uint64_t ttbr0, uint64_t page,
                                 uint64_t template_pte)
{
    hwaddr pte_pa = 0;
    uint64_t pte, new_pte;
    uint8_t zero[0x4000];
    MemTxResult tx;

    if (s->stack_fix_fills >= 8) {
        return false;
    }
    pte = sep_lab_ttbr0_l2_pte(as, ttbr0, page, &pte_pa);
    if (pte & 1) {
        return false;
    }
    if ((template_pte & 0x3) != 0x3 || !pte_pa) {
        return false;
    }
    if (!s->stack_fix_next_pa) {
        s->stack_fix_next_pa =
            (SEP_KRAM_BASE + SEP_KRAM_SIZE - 0x100000) & ~0x3fffULL;
    }
    if (s->stack_fix_next_pa < SEP_KRAM_BASE + 0x800000) {
        error_report("SEP lab: sep-stack-fix phys pool exhausted");
        return false;
    }
    s->stack_fix_next_pa -= 0x4000;
    memset(zero, 0, sizeof(zero));
    address_space_write(as, s->stack_fix_next_pa, MEMTXATTRS_UNSPECIFIED,
                        zero, sizeof(zero));
    /* Clone output-addr from pool; force AF + AP=01 (EL1/EL0 RW) so the
     * page is usable as an EL0 stack. Keep AttrIndx/SH from template. */
    new_pte = (template_pte & ~0xffffffffc000ULL) |
              (s->stack_fix_next_pa & 0xffffffffc000ULL);
    new_pte |= (1ULL << 10);              /* AF */
    new_pte = (new_pte & ~0xc0ULL) | 0x40; /* AP = 01 */
    address_space_stq_le(as, pte_pa, new_pte, MEMTXATTRS_UNSPECIFIED, &tx);
    if (tx != MEMTX_OK) {
        return false;
    }
    s->stack_fix_fills++;
    error_report("SEP lab: sep-stack-fix fill #%u VA 0x%llx -> PA 0x%llx",
                 s->stack_fix_fills,
                 (unsigned long long)page,
                 (unsigned long long)s->stack_fix_next_pa);
    return true;
}

static bool sep_lab_map_stack_page(AppleSEPLabState *s, ARMCPU *cpu,
                                     uint64_t va_page)
{
    AddressSpace *as;
    uint64_t ttbr0, template = 0, e;
    int i;

    if (va_page < 0x4000 || va_page > 0x8000000ULL) {
        return false;
    }
    as = cpu_get_address_space(CPU(cpu), ARMASIdx_NS);
    ttbr0 = cpu->env.cp15.ttbr0_el[1];
    if (!ttbr0) {
        return false;
    }
    e = sep_lab_ttbr0_l2_pte(as, ttbr0, va_page, NULL);
    if (e & 1) {
        return false; /* already mapped — do not touch perms */
    }
    for (i = 1; i <= 2; i++) {
        uint64_t cand = sep_lab_ttbr0_l2_pte(as, ttbr0,
                                             va_page + (uint64_t)i * 0x4000,
                                             NULL);
        if ((cand & 0x3) == 0x3) {
            template = cand;
            break;
        }
        cand = sep_lab_ttbr0_l2_pte(as, ttbr0,
                                   va_page - (uint64_t)i * 0x4000, NULL);
        if ((cand & 0x3) == 0x3) {
            template = cand;
            break;
        }
    }
    if (!template) {
        return false;
    }
    if (sep_lab_fill_one_page(s, as, ttbr0, va_page, template)) {
        tlb_flush(CPU(cpu));
        return true;
    }
    return false;
}

static void sep_lab_stack_fix_hook(ARMCPU *cpu, void *opaque)
{
    AppleSEPLabState *s = opaque;
    uint64_t sp, page;

    if (!s->stack_fix || !s->seprom || arm_current_el(&cpu->env) != 0) {
        return;
    }
    sp = cpu->env.xregs[31] ? cpu->env.xregs[31] : cpu->env.sp_el[0];
    page = sp & ~0x3fffULL;
    /* SP page only — AP=00 neighbors stay as guest guards. */
    sep_lab_map_stack_page(s, cpu, page);
}

static void sep_lab_stack_fix_pre_hook(ARMCPU *cpu, void *opaque)
{
    AppleSEPLabState *s = opaque;
    CPUARMState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    uint64_t esr, far, sp, far_page, sp_page;
    unsigned dfsc;
    bool fixed = false;

    if (!s->stack_fix || !s->seprom || arm_current_el(env) != 0) {
        return;
    }
    if (cs->exception_index != EXCP_DATA_ABORT) {
        return;
    }
    esr = env->exception.syndrome;
    if (((esr >> 26) & 0x3f) != 0x24 && ((esr >> 26) & 0x3f) != 0x25) {
        return;
    }
    dfsc = esr & 0x3f;
    if (dfsc != 0x07) {
        if (dfsc == 0x0f) {
            far = env->exception.vaddress;
            sp = env->xregs[31] ? env->xregs[31] : env->sp_el[0];
            error_report("SEP lab: sep-stack-fix frontier Perm_L3 "
                         "FAR=0x%llx SP=0x%llx PC=0x%llx x0=0x%llx x2=0x%llx",
                         (unsigned long long)far, (unsigned long long)sp,
                         (unsigned long long)env->pc,
                         (unsigned long long)env->xregs[0],
                         (unsigned long long)env->xregs[2]);
        }
        return; /* guards / Perm stay guest-visible */
    }
    far = env->exception.vaddress;
    sp = env->xregs[31] ? env->xregs[31] : env->sp_el[0];
    far_page = far & ~0x3fffULL;
    sp_page = sp & ~0x3fffULL;
    /* FAR must sit on/next-to SP page (stack-shaped abort). */
    if (far_page != sp_page &&
        far_page + 0x4000 != sp_page &&
        sp_page + 0x4000 != far_page) {
        return;
    }
    fixed = sep_lab_map_stack_page(s, cpu, far_page);
    if (sp_page != far_page) {
        fixed = sep_lab_map_stack_page(s, cpu, sp_page) || fixed;
    }
    if (fixed) {
        error_report("SEP lab: sep-stack-fix retry FAR=0x%llx SP=0x%llx PC=0x%llx",
                     (unsigned long long)far, (unsigned long long)sp,
                     (unsigned long long)env->pc);
        cs->exception_index = -1;
        cpu_loop_exit(cs);
    }
}

static void sep_lab_init_stack_fix(AppleSEPLabState *s)
{
    if (!s->stack_fix) {
        return;
    }
    if (!s->seprom) {
        error_report("SEP lab: sep-stack-fix=on requires seprom=on; ignored");
        s->stack_fix = false;
        return;
    }
    /*
     * Back the low end of the memcfg DRAM window. Without this, cfg 0x9001f
     * claims [0x1e00000000, 0x1e40000000) but only kram@0x1e40000000 is RAM;
     * FMST/untyped retypes into the hole produce sparse/AP=00 stacks and the
     * post-PMGR Trans_L3 at SP.
     */
    memory_region_init_ram(&s->dram_lo, NULL, "sep-dram-lo",
                           SEP_DRAM_LO_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(&s->private_memory, SEP_DRAM_LO_BASE,
                                        &s->dram_lo, 0);
    arm_register_el_change_hook(s->cpu, sep_lab_stack_fix_hook, s);
    arm_register_pre_el_change_hook(s->cpu, sep_lab_stack_fix_pre_hook, s);
    error_report("SEP lab: sep-stack-fix on (DRAM lo 0x%llx/0x%llx + "
                 "FMST 32KiB + EL0 SP Trans_L3 filler)",
                 (unsigned long long)SEP_DRAM_LO_BASE,
                 (unsigned long long)SEP_DRAM_LO_SIZE);
}

static void sep_lab_init_timer(AppleSEPLabState *s)
{
    if (!s->sep_timer) {
        return;
    }
    if (!s->seprom) {
        error_report("SEP lab: sep-timer=on requires seprom=on; ignored");
        return;
    }
    memory_region_init_io(&s->timer_mr, NULL, &sep_timer_ops, s,
                          "sep-timer", 0x1000);
    memory_region_add_subregion_overlap(&s->private_memory, SEP_TIMER_PA,
                                        &s->timer_mr, 20);
    memory_region_init_io(&s->kic_mr, NULL, &sep_kic_ops, s,
                          "sep-kic-event", 0x100);
    memory_region_add_subregion_overlap(&s->private_memory, SEP_KIC_EVT_PA,
                                        &s->kic_mr, 20);
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, sep_timer_fire, s);
    error_report("SEP lab: sep-timer on (timer 0x%llx; plat 0x%llx; "
                 "kic 0x%llx/0x%llx; pmgr 0x%llx/0x%llx; excl 0x%llx)",
                 SEP_TIMER_PA, SEP_ASC_PA,
                 SEP_KIC_PA, SEP_KIC_SIZE,
                 SEP_PMGR_PA, SEP_PMGR_SIZE, SEP_EXCL_PA);
}

static bool sep_lab_get_sep_timer(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->sep_timer;
}

static void sep_lab_set_sep_timer(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->sep_timer = value;
}

static bool sep_lab_get_sep_trng_irq(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->sep_trng_irq;
}

static void sep_lab_set_sep_trng_irq(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->sep_trng_irq = value;
}

static bool sep_lab_get_sep_phase2(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->sep_phase2;
}

static void sep_lab_set_sep_phase2(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->sep_phase2 = value;
}

static bool sep_lab_get_seprom(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->seprom;
}

static void sep_lab_set_seprom(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->seprom = value;
}

static bool sep_lab_get_stack_fix(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->stack_fix;
}

static void sep_lab_set_stack_fix(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->stack_fix = value;
}

static char *sep_lab_get_ap_probe(Object *obj, Error **errp)
{
    return g_strdup_printf("0x%" PRIx64, APPLE_SEP_LAB(obj)->last_ap_probe);
}

/*
 * Host-only QOM debugger operation, not a guest register or SEP command.
 * This fork has no -qtest CLI.  Keep AP-window testing independent of the
 * SEP CPU's private address space instead of aliasing AP MMIO into that map.
 */
static void sep_lab_set_ap_probe(Object *obj, const char *value, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);
    uint64_t address;
    uint32_t discarded;
    bool valid = false;

    if (!s->cpu) {
        error_setg(errp, "x-ap-probe is available only after machine init");
        return;
    }
    if (qemu_strtou64(value, NULL, 0, &address) < 0 || (address & 3)) {
        error_setg(errp, "x-ap-probe requires an aligned AP physical address");
        return;
    }
    for (unsigned i = 0; i < ARRAY_SIZE(d47_ap_regions); i++) {
        uint64_t base = d47_ap_regions[i].address;
        uint64_t size = d47_ap_regions[i].size;
        if (address >= base && address - base <= size - sizeof(discarded)) {
            valid = true;
            break;
        }
    }
    if (!valid) {
        error_setg(errp, "x-ap-probe is outside the observed D47 AP windows");
        return;
    }
    s->last_ap_probe = address;
    if (address_space_read(&address_space_memory, address,
                           MEMTXATTRS_UNSPECIFIED, &discarded,
                           sizeof(discarded)) == MEMTX_OK) {
        error_setg(errp, "unimplemented AP probe unexpectedly succeeded");
    }
}

static bool sep_lab_get_sep_inject(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->sep_inject;
}

static void sep_lab_set_sep_inject(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->sep_inject = value;
}

static char *sep_lab_get_inject_script(Object *obj, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);

    return g_strdup(s->inject_script ? s->inject_script : "");
}

static void sep_lab_set_inject_script(Object *obj, const char *value, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);

    g_free(s->inject_script);
    s->inject_script = g_strdup(value ? value : "");
}

static char *sep_lab_get_inject_kic(Object *obj, Error **errp)
{
    return g_strdup_printf("0x%x", APPLE_SEP_LAB(obj)->mbox_kic_event);
}

static void sep_lab_set_inject_kic(Object *obj, const char *value, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);
    uint64_t v;

    if (qemu_strtou64(value, NULL, 0, &v) < 0) {
        error_setg(errp, "x-inject-kic expects a KIC event word");
        return;
    }
    s->mbox_kic_event = (uint32_t)v;
    error_report("SEP inject: KIC event now 0x%x", s->mbox_kic_event);
}

static char *sep_lab_get_trng_fire(Object *obj, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);

    return g_strdup_printf("pending=%d mask=0x%x", s->trng_pending,
                           s->ext_irq_mask);
}

static void sep_lab_set_trng_fire(Object *obj, const char *value, Error **errp)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);

    (void)value;
    if (!s->sep_trng_irq) {
        error_setg(errp, "x-trng-fire needs sep-trng-irq=on");
        return;
    }
    s->ext_irq_mask &= ~SEP_EXT_IRQ_TRNG;
    s->trng_regs[0x14 / 4] |= 0x8000u;
    s->trng_pending = true;
    sep_lab_update_irq(s);
    error_report("SEP TRNG: host fire KIC 0x%x (mask now 0x%x CTRL=0x%x)",
                 SEP_KIC_TRNG_EVENT, s->ext_irq_mask, s->trng_regs[0x14 / 4]);
}

static void sep_lab_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Isolated SEP development lab (not a complete T8140 SEP)";
    mc->init = sep_lab_init;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("max");
    mc->max_cpus = 1;
    mc->default_ram_size = 16 * MiB;
    mc->default_ram_id = "apple-sep-lab.ram";
    mc->no_cdrom = true;
    mc->no_floppy = true;
    mc->no_parallel = true;
    object_class_property_add_str(oc, "trace-file", sep_lab_get_trace,
                                  sep_lab_set_trace);
    object_class_property_set_description(oc, "trace-file",
        "JSONL metadata trace; unknown-MMIO values are not logged");
    object_class_property_add_str(oc, "entry", sep_lab_get_entry,
                                  sep_lab_set_entry);
    object_class_property_set_description(oc, "entry",
        "Raw image entry offset in lab RAM (default 0)");
    object_class_property_add_str(oc, "x-ap-probe", sep_lab_get_ap_probe,
                                  sep_lab_set_ap_probe);
    object_class_property_set_description(oc, "x-ap-probe",
        "Host-only debugger read of an AP window; NOT a SEP wire operation");
    object_class_property_add_str(oc, "x-irq", sep_lab_get_irq,
                                  sep_lab_set_irq);
    object_class_property_set_description(oc, "x-irq",
        "Host-only: set 1/0 to raise/lower the SEP cpu IRQ (wake the WFE); not a "
        "SEP wire op. Placeholder until the ASC-v6 mailbox drives this line.");
    object_class_property_add_bool(oc, "discover", sep_lab_get_discover,
                                   sep_lab_set_discover);
    object_class_property_set_description(oc, "discover",
        "Reconnaissance mode (default off): model SEP IMPDEF sysregs, back the "
        "SEP SRAM, and log unknown MMIO (returning 0) instead of faulting, so "
        "one boot traces the SEP's register map. Fabricates no protocol reply.");
    object_class_property_add_bool(oc, "sep-timer", sep_lab_get_sep_timer,
                                   sep_lab_set_sep_timer);
    object_class_property_set_description(oc, "sep-timer",
        "Lab-only (needs seprom=on): model the SEP-private timer at "
        "0x2a0e40000 and the KIC +0x818 event claim, wired to the SEP IRQ");
    object_class_property_add_bool(oc, "sep-trng-irq", sep_lab_get_sep_trng_irq,
                                   sep_lab_set_sep_trng_irq);
    object_class_property_set_description(oc, "sep-trng-irq",
        "Lab-only (default off; needs seprom=on): on TRNG.CTRL bit15 go, post "
        "KIC +0x818 event 0x10003 (IRQ 3) if ASC ext-IRQ bit3 is unmasked "
        "(+0xa80 write 0x8). Phase-2 lead: sks entropy before AKF mailbox.");
    object_class_property_add_bool(oc, "sep-phase2", sep_lab_get_sep_phase2,
                                   sep_lab_set_sep_phase2);
    object_class_property_set_description(oc, "sep-phase2",
        "Lab-only (default off; needs seprom=on): after EPControl create "
        "(AKF/MBOX + TRNG), call start-all so AKF binds IRQ 0x80 and unmasks "
        "ASC IOP_NONEMPTY. Stands in for the sks libShared RPC 0x4047 that "
        "does not run before idle in this lab.");
    object_class_property_add_bool(oc, "seprom", sep_lab_get_seprom,
                                   sep_lab_set_seprom);
    object_class_property_set_description(oc, "seprom",
        "SEPROM-handoff reconnaissance (default off; implies discover): also "
        "back the SEP DRAM carveout and the memory-config register pages as RAM "
        "so the boot handoff (HW regs, BPSE boot-args, boot-role pointer) can be "
        "poked with gdb and iterated to drive sepOS onto its build path.");
    object_class_property_add_bool(oc, "sep-stack-fix", sep_lab_get_stack_fix,
                                   sep_lab_set_stack_fix);
    object_class_property_set_description(oc, "sep-stack-fix",
        "Lab-only (needs seprom=on, default off): back memcfg DRAM lo "
        "(0x1e00000000/64MiB), grow FMST carve to 32KiB, and fill missing "
        "EL0 SP 16K pages on Trans_L3 (synthetic stack hole after PMGR).");
    object_class_property_add_bool(oc, "sep-inject", sep_lab_get_sep_inject,
                                   sep_lab_set_sep_inject);
    object_class_property_set_description(oc, "sep-inject",
        "Lab-only (default off; needs seprom=on): ASC-v6 mailbox injector at "
        "0x2a2404100 — AP->SEP A2I FIFO, KIC 0x40000 doorbell, I2A capture. "
        "Use QOM x-inject / x-outbox. Fabricates no SEP replies.");
    object_class_property_add_str(oc, "sep-inject-script",
                                  sep_lab_get_inject_script,
                                  sep_lab_set_inject_script);
    object_class_property_set_description(oc, "sep-inject-script",
        "Optional comma list of named msgs (ping,status,alive,epmap,sksopen) "
        "queued at reset after the boot 0xfe descriptor; doorbell on each.");
    object_class_property_add_str(oc, "x-inject", sep_lab_get_inject,
                                  sep_lab_set_inject);
    object_class_property_set_description(oc, "x-inject",
        "Host-only: enqueue mailbox msg(s). Names: ping|status|alive|epmap|sksopen|"
        "ctrl-nop|ool-in-addr|ool-out-addr|ool-in-size|ool-out-size|secmode|"
        "selftest|ctrl-handshake; "
        "or ep,tag,op[,param[,data]]; or hex:<32 hex>; separate with ; or +.");
    object_class_property_add_str(oc, "x-outbox", sep_lab_get_outbox,
                                  sep_lab_set_outbox);
    object_class_property_set_description(oc, "x-outbox",
        "Host-only: dump captured SEP->AP I2A frames; write clear/0 to reset log.");
    object_class_property_add_str(oc, "x-inject-kic", sep_lab_get_inject_kic,
                                  sep_lab_set_inject_kic);
    object_class_property_set_description(oc, "x-inject-kic",
        "Host-only: KIC +0x818 event word for doorbell (default 0x40000 = "
        "IRQ_IOP_NONEMPTY). Use to probe which irq vector sepOS handles.");
    object_class_property_add_str(oc, "x-trng-fire", sep_lab_get_trng_fire,
                                  sep_lab_set_trng_fire);
    object_class_property_set_description(oc, "x-trng-fire",
        "Host-only: post TRNG KIC 0x10003 (IRQ 3) now; clears ext-mask bit3.");
}

static void sep_lab_finalize(Object *obj)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);

    g_free(s->inject_script);
    if (s->cpu) {
        qemu_unregister_reset(sep_lab_reset, s);
    }
    if (s->migration_blocker) {
        migrate_del_blocker(&s->migration_blocker);
    }
    if (s->trace && s->trace != stderr) {
        fclose(s->trace);
    }
    g_free(s->trace_path);
}

static const TypeInfo sep_lab_type = {
    .name = TYPE_APPLE_SEP_LAB,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(AppleSEPLabState),
    .instance_finalize = sep_lab_finalize,
    .class_init = sep_lab_class_init,
};

static void sep_lab_register_types(void)
{
    type_register_static(&sep_lab_type);
}

type_init(sep_lab_register_types)
