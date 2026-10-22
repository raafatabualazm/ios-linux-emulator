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
    MemoryRegion cfg0800;       /* memory-config regs 0x2a0800xxx as RAM        */
    MemoryRegion cfg0c40;       /* memory-config regs 0x2a0c40xxx as RAM        */
    MemoryRegion fuse;          /* SEP security-fuse shadow at 0x2e42c8000      */
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
    QEMUTimer *timer;
    uint32_t t_ctrl, t_stat, t_count;
    bool t_pending;
    uint64_t t_fires, t_claims;
    Error *migration_blocker;
};

#define SEP_TIMER_PA   0x2a0e40000ULL
#define SEP_KIC_EVT_PA 0x2a2400800ULL   /* window covers KIC +0x800..+0x8ff */
#define SEP_TIMER_HZ   24000000ULL
#define SEP_KIC_TIMER_EVENT 0x00070001u /* type 7, bit0 valid, bit3 clear */
static void sep_lab_init_timer(AppleSEPLabState *s);

/* SEP DRAM carveout for seprom mode (point the memory-config regs here). */
#define SEP_CARVEOUT_BASE 0x2a4000000ULL
/* SEP kernel RAM region: sepOS's build path allocates its page tables here
 * (desc->base 0x1e40024000, from a base hardcoded in the image at 0x6b10,
 * discovered live). MMU is off during the build, so these are physical. */
#define SEP_KRAM_BASE 0x1e40000000ULL
#define SEP_KRAM_SIZE 0x10000000ULL  /* 256 MiB */
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
        bpse[0x78 / 4] = 0x4000;
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
    cfg0800 = memory_region_get_ram_ptr(&s->cfg0800);
    /*
     * DRAM-window sizing word: 0x9001f makes the roottask's SEP DRAM window
     * exactly [0x1e00000000, 0x1e40000000), which passes its region-table
     * consistency check at 0x10218 (0x2a3fff failed it).
     */
    cfg0800[0x408 / 4] = 0x9001f;
    cfg0800[0x410 / 4] = 0;
    cfg0800[0x418 / 4] = 0;
    cfg0c40 = memory_region_get_ram_ptr(&s->cfg0c40);
    cfg0c40[0x180 / 4] = 4;
    cfg0c40[0x1a0 / 4] = 0x4000;
    /* Fuse already seeded at init; re-seed in case of soft reset wipe. */
    {
        uint32_t *fz = (uint32_t *)memory_region_get_ram_ptr(&s->fuse);
        fz[0] = 0xa55ac33c;
        fz[1] = 0xa55ac33c;
    }
    sepmmio = memory_region_get_ram_ptr(&s->sepmmio);
    sepmmio[0x404810 / 4] = 0x040000fe;
    sepmmio[0x404814 / 4] = 0x10000000;
    /* boot-role = BPSE|1 (cold build path); ready bit stays 1. */
    s->cpu->env.apple_modern_sep_store[14] = 0x2a0210000ULL | 1ULL;
    s->cpu->env.apple_modern_sep_store[13] = 1ULL;
    sep_lab_write_region_blob(s);
}

static void sep_lab_reset(void *opaque)
{
    AppleSEPLabState *s = opaque;

    cpu_reset(CPU(s->cpu));
    cpu_set_pc(CPU(s->cpu), s->entry);
    sep_lab_seed_handoff(s);
    s->faulted = false;
    s->reset_generation++;
    sep_lab_trace_reset(s);
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
        memory_region_init_ram(&s->cfg0800, NULL, "sep-cfg0800", 0x10000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2a0800000ULL,
                                            &s->cfg0800, 0);
        memory_region_init_ram(&s->cfg0c40, NULL, "sep-cfg0c40", 0x10000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2a0c40000ULL,
                                            &s->cfg0c40, 0);
        /* SEP security-fuse shadow. sepOS's secfuse init (image 0x8d80) maps
         * PA 0x2e42c8000 (16 KiB) and asserts (secfuse.c:52, panic thunk
         * 0xa23c) that fuse words [0] and [1] each equal one of two hardcoded
         * sentinels built at image 0x8d38: 0xa55ac33c or 0xa050c030. Back it as
         * RAM and seed the sentinels so sepOS proceeds; remaining fuse fields
         * are discovered by iteration (gdb pokes this RAM). */
        memory_region_init_ram(&s->fuse, NULL, "sep-fuse", 0x10000,
                               &error_fatal);
        memory_region_add_subregion_overlap(&s->private_memory, 0x2e42c8000ULL,
                                            &s->fuse, 0);
        {
            uint32_t *fz = (uint32_t *)memory_region_get_ram_ptr(&s->fuse);
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


static void sep_timer_update_irq(AppleSEPLabState *s)
{
    qemu_set_irq(s->sep_irq, s->t_pending);
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
    error_report("SEP lab: sep-timer on (timer 0x%llx, KIC event 0x%llx)",
                 SEP_TIMER_PA, SEP_KIC_EVT_PA + 0x18);
}

static bool sep_lab_get_sep_timer(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->sep_timer;
}

static void sep_lab_set_sep_timer(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->sep_timer = value;
}

static bool sep_lab_get_seprom(Object *obj, Error **errp)
{
    return APPLE_SEP_LAB(obj)->seprom;
}

static void sep_lab_set_seprom(Object *obj, bool value, Error **errp)
{
    APPLE_SEP_LAB(obj)->seprom = value;
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
    object_class_property_add_bool(oc, "seprom", sep_lab_get_seprom,
                                   sep_lab_set_seprom);
    object_class_property_set_description(oc, "seprom",
        "SEPROM-handoff reconnaissance (default off; implies discover): also "
        "back the SEP DRAM carveout and the memory-config register pages as RAM "
        "so the boot handoff (HW regs, BPSE boot-args, boot-role pointer) can be "
        "poked with gdb and iterated to drive sepOS onto its build path.");
}

static void sep_lab_finalize(Object *obj)
{
    AppleSEPLabState *s = APPLE_SEP_LAB(obj);

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
