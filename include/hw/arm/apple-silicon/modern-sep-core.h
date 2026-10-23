/*
 * apple-modern SEP core: a second modern Apple CPU executing real (decrypted)
 * sepOS in its own address space. Opt-in, default off. See modern-sep-core.c.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef HW_ARM_APPLE_MODERN_SEP_CORE_H
#define HW_ARM_APPLE_MODERN_SEP_CORE_H

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "system/memory.h"
#include "target/arm/cpu-qom.h"
#include "hw/irq.h"

/*
 * SEPROM-equivalent handoff (lab-proven on apple-sep-lab,seprom=on): BPSE
 * boot-args, memory-config regs, fuse/XPRT/EXCL/plat sentinels, PMGR+TRNG,
 * timer+KIC, 24 MHz cntfrq, and the kernel image at PA 0x1e40000000.
 * Synthetic identity — research vehicle for the AP-facing protocol, not a
 * faithful D47 SEP. Gated behind sep-core=on (itself default off).
 */
#define SEP_CORE_KRAM_BASE      0x1e40000000ULL
#define SEP_CORE_KRAM_SIZE      0x10000000ULL   /* 256 MiB */
#define SEP_CORE_DRAM_LO_BASE   0x1e00000000ULL
#define SEP_CORE_DRAM_LO_SIZE   0x4000000ULL    /* 64 MiB (FMST carve) */
#define SEP_CORE_SRAM_BASE      0x2a0200000ULL
#define SEP_CORE_SRAM_SIZE      0x400000ULL     /* 4 MiB */
#define SEP_CORE_CARVEOUT_BASE  0x2a4000000ULL
#define SEP_CORE_CARVEOUT_SIZE  0x10000000ULL   /* 256 MiB */
#define SEP_CORE_BPSE_ADDR      0x2a0210000ULL
#define SEP_CORE_XPRT_BASE      0x2e42c0000ULL
#define SEP_CORE_XPRT_SIZE      0x30000ULL
#define SEP_CORE_FUSE_OFF       0x8000ULL       /* fuse shadow inside XPRT */
#define SEP_CORE_SEPMMIO_BASE   0x2a2000000ULL
#define SEP_CORE_SEPMMIO_SIZE   0x1000000ULL    /* 16 MiB */
#define SEP_CORE_CNTFRQ         24000000ULL
#define SEP_CORE_REGION_BASE    0x10000000000ULL
#define SEP_CORE_REGION_SIZE    0x1000000ULL

/* PMGR / SSEASMBT window (lab): includes +0x2c000 status mirroring. */
#define SEP_CORE_PMGR_PA        0x2a0800000ULL
#define SEP_CORE_PMGR_SIZE      0x80000ULL
/* EXCL (AKPLCXE): [+0]==[+8]==0xa55ac33c */
#define SEP_CORE_EXCL_PA        0x2a1000000ULL
#define SEP_CORE_EXCL_SIZE      0x4000ULL
#define SEP_CORE_SENTINEL       0xa55ac33cu
/* Loader KIC window 0x2a0c40000/0x40000; ASC KIC claim at mbox+0x818. */
#define SEP_CORE_KIC_PA         0x2a0c40000ULL
#define SEP_CORE_KIC_SIZE       0x40000ULL
#define SEP_CORE_TRNG_PA        0x2a0b80000ULL
#define SEP_CORE_TRNG_SIZE      0x1000ULL
#define SEP_CORE_TIMER_PA       0x2a0e40000ULL
#define SEP_CORE_TIMER_HZ       24000000ULL
#define SEP_CORE_KEY_FCFG_PA    0x2a0e48000ULL
#define SEP_CORE_PLAT_PA        0x2a0d80000ULL
#define SEP_CORE_PLAT_SIZE      0x100000ULL

/*
 * M3: AP APPLE_A7IOP_V6 at 0x282600000 (+0x8100 AP mailbox) is shared; SEP
 * sees the same wrapper at SEP_CORE_MBOX_BASE (+0x4100 IOP view). KIC status
 * +0x818 maps to IRQ 0x80 / 0x83 (IOP_NONEMPTY / related).
 */
#define SEP_CORE_MBOX_BASE      0x2a2400000ULL
#define SEP_CORE_KIC_EVT_PA     (SEP_CORE_MBOX_BASE + 0x800ULL)
#define SEP_CORE_KIC_TIMER_EVT  0x00070001u
#define SEP_CORE_KIC_MBOX_EVT   0x00040000u
#define SEP_CORE_KIC_TRNG_EVT   0x00010003u /* type1 id3 → IRQ 3 */

/* EPControl file offsets inside sepos.j410 (Mach-O @ 0x74000). */
#define SEP_CORE_EP_FILE        0x74000u
#define SEP_CORE_EP_TEXT_VA     0x110000u
#define SEP_CORE_EP_FO(va)      (SEP_CORE_EP_FILE + ((va) - SEP_CORE_EP_TEXT_VA))
#define SEP_CORE_EP_START_ALL   0x118498u
#define SEP_CORE_EP_START_EXIT  0x118524u
#define SEP_CORE_EP_CREATE_RET  0x118e6cu
#define SEP_CORE_EP_TRAMP       0x123000u

typedef struct AppleModernSEPCore {
    ARMCPU *cpu;
    AddressSpace as;
    MemoryRegion container;
    MemoryRegion ram;           /* small lab RAM at PA 0 */
    MemoryRegion dram_lo;       /* 0x1e00000000 — FMST / memcfg 0x9001f window */
    MemoryRegion kram;
    MemoryRegion sram;
    MemoryRegion carveout;
    MemoryRegion pmgr_mr;       /* IO: PMGR 0x2a0800000/0x80000 */
    MemoryRegion cfg0c40;       /* KIC/memcfg RAM 0x2a0c40000/0x40000 */
    MemoryRegion excl;
    MemoryRegion akp_sab;
    MemoryRegion akp_mmt;
    MemoryRegion akp_hi;
    MemoryRegion trng_mr;
    MemoryRegion key_fcfg_mr;
    MemoryRegion plat;
    MemoryRegion xprt;          /* 0x2e42c0000/0x30000 (MISC+FUSE+UCES) */
    MemoryRegion sepmmio;
    MemoryRegion region;
    MemoryRegion timer_mr;
    MemoryRegion kic_mr;        /* ASC +0x800.. claim at +0x818 */
    MemoryRegion asc_a00_mr;    /* ASC +0xa00 MASK_SET / +0xa80 MASK_CLR */
    MemoryRegion mmio;
    MemoryRegion mbox_alias;    /* SEP view of shared ASC-v6 */
    MemoryRegion ap_alias;      /* system_memory: AP OOL/shmbuf reachability */
    qemu_irq sep_irq;
    bool mailbox_attached;
    bool ap_alias_attached;
    uint64_t ram_size;
    uint64_t entry;
    gsize image_size;
    bool seprom_handoff;

    /* PMGR / TRNG / timer / KIC state (lab models). */
    uint32_t *pmgr_regs;
    uint32_t trng_regs[SEP_CORE_TRNG_SIZE / 4];
    uint32_t ext_irq_mask;
    uint32_t key_fcfg_8000;
    uint32_t t_ctrl;
    uint32_t t_stat;
    uint32_t t_count;
    bool t_pending;
    bool trng_pending;
    bool mbox_pending;
    bool mbox_line;             /* live a7iop SEP-iop IRQ level */
    bool boot_desc_sent;
    /* SEPROM bootstrap-endpoint shim (SEP_CORE_ROMSHIM=off disables). */
    bool rom_shim;
    bool rom_announced;
    uint32_t rom_status;
    uint32_t rom_ops;
    uint32_t mbox_claims;
    struct AppleA7IOP *a7iop;
    uint64_t t_fires;
    QEMUTimer *timer;

    /* SEP_CORE_WATCH diagnostic (default off). */
    QEMUTimer *watch_timer;
    uint64_t watch_ms;
    uint64_t watch_last_pc;
    uint64_t watch_last_esr;
    uint64_t watch_last_elr;
    /* SEP_CORE_EXCLOG=<n>: EL0 exception log (diagnostic, default off). */
    uint32_t exclog_max;
    uint32_t exclog_n;
    uint32_t exclog_svc_hits;
    uint32_t exclog_ring_pos;
    uint64_t exclog_ring[64][8];
} AppleModernSEPCore;

struct AppleA7IOP;
bool apple_modern_sep_core_attach_mailbox(AppleModernSEPCore *core,
                                          struct AppleA7IOP *a7iop,
                                          Error **errp);

bool apple_modern_sep_core_create(Object *owner, AppleModernSEPCore *core,
                                  const char *cpu_type, uint64_t cntfrq,
                                  const char *image_path, Error **errp);

#endif /* HW_ARM_APPLE_MODERN_SEP_CORE_H */
