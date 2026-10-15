/* Declared PMGR register storage for the registers ApplePMGR::start programs.
 * See the header for what is attested and what is declared.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "migration/vmstate.h"
#endif
#include "hw/arm/apple-silicon/modern-pmgr-storage.h"

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
static void error_setg(Error **errp, const char *format, ...)
{
    if (errp) {
        va_list args;
        if (*errp) {
            abort();
        }
        *errp = calloc(1, sizeof(**errp));
        if (!*errp) {
            abort();
        }
        va_start(args, format);
        vsnprintf((*errp)->message, sizeof((*errp)->message), format, args);
        va_end(args);
    }
}
#endif

#define GROUP_RECORD 36
#define COUNTER_RECORD 64
#define MAX_GROUPS 32
#define MAX_COUNTERS 1024
#define MAX_REG_ENTRIES 64
#define VOTER_RAILS 4
#define VOTER_RAIL_RECORD 24
#define SOC_CLUSTERS 5
#define SOC_CLUSTER_RECORD 28
#define SOC_CLUSTER_AVE 2
/* perf-groups word 2 bit 1: ApplePMGR programs this group after initDriver. */
#define GROUP_PROGRAMMED 2

static bool aliases(const void *a, size_t as, const void *b, size_t bs)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return as && bs && (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y ||
                       (x < y + bs && y < x + as));
}

static bool overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    return as && bs && (as > UINT64_MAX - a || bs > UINT64_MAX - b ||
                       (a < b + bs && b < a + as));
}

static uint32_t le32(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
    return le32(p) | (uint64_t)le32(p + 4) << 32;
}

typedef struct Group {
    uint32_t reg_index, base, flags;
    uint32_t end;                                     /* bytes covered, multiple of 4 */
    uint64_t valid[APPLE_MODERN_PMGR_STORAGE_MASKS];
} Group;

static bool translate(AppleModernBlob ranges, uint64_t child, uint64_t size,
                      uint64_t *physical)
{
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t c = le64(ranges.data + i);
        uint64_t p = le64(ranges.data + i + 8);
        uint64_t n = le64(ranges.data + i + 16);
        if (child >= c && child - c <= n && size <= n - (child - c) &&
            p <= UINT64_MAX - (child - c) && p + (child - c) <= UINT64_MAX - size) {
            *physical = p + (child - c);
            return true;
        }
    }
    return false;
}

/* True if [physical, physical + size) lies inside one /arm-io range's parent side. */
static bool physical_in_ranges(AppleModernBlob ranges, uint64_t physical, uint64_t size)
{
    for (size_t i = 0; i < ranges.size; i += 24) {
        uint64_t p = le64(ranges.data + i + 8);
        uint64_t n = le64(ranges.data + i + 16);
        if (physical >= p && physical - p <= n && size <= n - (physical - p)) {
            return true;
        }
    }
    return false;
}

/* Record one 32-bit register of programmed group g; fail on a malformed record. */
static bool mark(Group *groups, unsigned group_count, AppleModernBlob reg,
                 unsigned group, uint64_t offset, Error **errp)
{
    if (group >= group_count) {
        error_setg(errp, "PMGR perf counter names group %u of %u", group, group_count);
        return false;
    }
    Group *g = &groups[group];
    uint64_t reg_size = le64(reg.data + 16 * g->reg_index + 8);
    if ((offset & 3) || offset > APPLE_MODERN_PMGR_STORAGE_MAX_SPAN - 4 ||
        (uint64_t)g->base + offset > reg_size || reg_size - (g->base + offset) < 4) {
        error_setg(errp, "PMGR perf register +0x%" PRIx64 " of group %u is unaligned, "
                   "too far from the base or outside its reg window", offset, group);
        return false;
    }
    g->valid[offset / 4 / 64] |= UINT64_C(1) << ((offset / 4) % 64);
    if (offset + 4 > g->end) {
        g->end = offset + 4;
    }
    return true;
}

#define ARRAY_ENTRIES(a) (sizeof(a) / sizeof((a)[0]))
#define FIXED_TAG_BASE 0x100

/*
 * Windows whose registers are named by BootKC constants rather than by an ADT
 * table. Each row is a RegMap reg_index (index into /arm-io/pmgr reg), an offset
 * in that window and a byte size; every 4-byte slot is a listed register.
 *  0: NUB_FR_GLOBAL_AP_CONTROLS (reg 4, RegMap selector 66, 0x308004000) +0x8..+0x24:
 *     the AP wake-source mask. AppleT8140PMGR's routine at 0xfffffff009848954
 *     (vtable slot 0x9c8; ApplePMGR's vtable+0x980 routine at 0xfffffff0092a5854
 *     tail-calls it with this+0x6b1c4) checks the requested 8 words against the
 *     supported ones, then writes supported & ~requested to offsets 0x4008 ..
 *     0x4024 (minus 0x4000) through 0xfffffff009848b10. Writes only; no read-back
 *     and no poll. The status words at +0x28..+0x44, read by 0xfffffff009848bb4,
 *     are not listed: nothing on the start path was seen to read them.
 *  1-3: PMS_PTS_PTD (reg 34, RegMap selector 8, 0x3003c0000) +0x18200, +0x18300 and
 *     +0x18400: the PTD interrupt block ApplePMGR configures from _initPMPv2
 *     (0xfffffff00928e304 -> loop at 0xfffffff00928ec40 -> vtable slot 0x950 =
 *     0xfffffff0092bd6f0 -> gated action 0xfffffff0092bd800, opcode 3). Per PTD
 *     entry it does, in this order, a read-modify-write of one vector-config
 *     field (0xfffffff0092e29bc; offset 0x18400 + ((e / 8) * 4 + ((e / 4) & 1) *
 *     0x200) for ptd-driver-version 1, field mask 0x1f at bit 8 * (e % 4); version 0
 *     would use (e / 8) * 4 with 4-bit fields; the ADT carries version 1 on
 *     /arm-io/pmp/iop-pmp-nub, and that the PTD object reads that node was not
 *     verified, so the extent below covers both layouts) and a
 *     write of 1 << (e % 32) to the enable-set bank at 0x18200 + 4 * (e / 32)
 *     (0xfffffff0092e2aec); the matching enable-clear bank is 0x18300 + 4 * (e / 32)
 *     (0xfffffff0092e2b6c). The extents here are the full banks for the 1024
 *     entries of the PTD. ADT /arm-io/aon-ptd names the same bank layout for its own
 *     instance (ptd-int-status-offset 0x0, -enable 0x100, -enable-set 0x200,
 *     -enable-clr 0x300), which is the analogy for reading +0x200 / +0x300 as
 *     write-one-to-set / write-one-to-clear enable banks; this model keeps plain
 *     storage (no W1S/W1C effect, no status) because nothing on this path reads
 *     either bank back. The status bank (+0x18000, read by opcode 5) and the
 *     enable register (+0x18100) are deliberately NOT listed.
 *  4: PMGR_SOC_CLUSTER_CTL (reg 28, RegMap selector 98, 0x300780000; reg 37 repeats the
 *     same range, and /arm-io/mcc reg[0] panic-save is the same physical page, which
 *     no model here owns) +0x0..+0x10, five registers (ADT ids 0..4). ApplePMGR's start calls vtable slot
 *     0x590 (AppleT8140PMGR wrapper 0xfffffff009847d84, then slot 0x9f0) which reaches
 *     the cluster power routine at 0xfffffff009847bf0 with index 0 and enable 1: it
 *     reads the register (readPMGRSOCClusterCtlReg, 0xfffffff0092b09f8), writes it back
 *     with the low nibble set to 0xf ((v & ~0xf) | 0xf), then calls
 *     waitPMGRSOCClusterCtlReg (0xfffffff0092b0adc -> generic wait 0xfffffff0092afba0)
 *     with offset 0, mask 0x10, value 0 and a 1 s timeout: it re-reads the register
 *     until (v & 0x10) == 0, and on timeout panics only if this+0x16d bit 0 is set.
 *     THIS IS A POLL. Zero-reset storage satisfies it on the first read only because
 *     the driver writes just the low nibble and bit 4 never becomes set; real
 *     hardware presumably raises bit 4 while the cluster power transition is pending.
 *     That timing is NOT modelled (declared: the transition completes instantly), and
 *     a driver that ever wrote bit 4 would hang here. The routine is called a second
 *     time with index 1, which does the identical read, write ((v & ~0xf) | 0xf) and
 *     wait at +0x4 (measured as the next frontier after +0x0 alone was listed).
 *  5-6: PMGR_SOC_PWRGATE (reg 22, RegMap selector 101, 0x300724000) +0x0 and +0x40.
 *     Right after the two cluster calls the same AppleT8140PMGR wrapper
 *     (0xfffffff009847d84, ApplePMGR start's vtable slot 0x590) reads PwrGate +0x0
 *     through vtable slot 0xd38 (readPMGRSOCPwrGateReg, 0xfffffff0092b0668) and writes
 *     it back with bit 31 set through slot 0xd40 (0xfffffff0092b06d8), then does the
 *     same at +0x40 (0xfffffff009847e44 .. 0xfffffff009847f34). Plain
 *     read-modify-write with no wait. The code after it (0xfffffff00984812c: a
 *     read-modify-write of PMGR_SOC_TVM +0xc00 followed by an unbounded poll for bit
 *     11 clear, and a mask-driven loop at 0xfffffff009848214) is NOT covered here.
 *  7-16: PMGR_SOC_DPE (reg 32, RegMap selector 78 = 0x4e, 0x300208000), ten channels
 *     at +0x2400 + 0x400 * n (the byte table at 0xfffffff0077b1f70 holds
 *     0x2400, 0x2800, ... 0x4800). AppleT8140PMGR's energy-accumulator routine at
 *     0xfffffff00984c1d0 (running only when the object byte at this+0x738e8 has bit 0
 *     set, which it had in the measured guest) loops 10 times over that table. Per
 *     channel it does a read-modify-write setting bit 0 at t + 0x200, then at t, then
 *     at t + 0x300; the middle one is skipped for exactly one iteration, the eighth
 *     (its countdown register x23 reaches 0 only there), so channel 7 lists only
 *     +0x200 and +0x300. Plain RMW, no wait: 29 registers in all.
 *  17: the PMC static-voter vote registers, in /arm-io/pmgr reg[43] (child 0xf2000000,
 *     physical 0x302000000, 16 MiB; RegMap selector 0x81, which the 43 pairs of initRegMap
 *     as decoded do not list), at offset 0x8ac000: ApplePMC register group
 *     kRegGroupPMCDVFM has base offset 0x800000 (MEASURED in guest memory at pmgr+0x6088)
 *     and AppleT8140PMC adds 0xac000. Four 32-bit registers at +0x0 .. +0xc. Reached
 *     from the base slot-0x5a0 routine 0xfffffff0092aac90 (called by the wrapper
 *     0xfffffff009847d84 at 0x9847fd0): for each die i < this+0x631c it calls the PMC
 *     object at this+0x738a0 through vtable slot 0x28, which reaches ApplePMC::restorePMC
 *     (0xfffffff0092e39e0); for each of the PMC's three voter agents (this+8, +0xc, +0x10 =
 *     PMP 0, CLPC 1, AP 3 here) it calls _enableStaticVoterInterface (0xfffffff0092e3b5c),
 *     which for every rail of the agent's mask does a read-modify-write of the register at
 *     0xac000 + 4 * rail (AppleT8140PMC read/write thunks 0xfffffff00984ccac and
 *     0xfffffff00984cc18, kind 0), setting the agent's bit (voter-agent byte 2). The rail
 *     index is the first u16 of the ADT voter-rail-data record (DCS 0, SOC 1, DISP 2,
 *     AVE 3), which the plan builder checks. Plain RMW, no wait: 4 registers (+0x0 .. +0xc).
 *     The same window also lists the dynamic-voter control register +0x24 (0x3028ac024:
 *     AppleT8140PMC kind 2). restorePMC's flag-bit-4 branch (ADT pmc-pmgr 0x3f has it) calls the T8140PMC
 *     vtable slot 0xa8 (0xfffffff00984cfa8, from restorePMC at 0xfffffff0092e3a98) with
 *     enable = 1 and flag = (this+0x3c != 0): a read-modify-write of 0xac024 to
 *     (v & ~3) | (enable ? 2 : 0) | flag, no poll. It then tail-calls vtable slot 0xa0
 *     (0xfffffff00984d0a8) with the value returned by slot 0xc0 (0xfffffff00984d5e8: -1),
 *     which writes 0xffffffff to PMC +0x60000.
 *  18: PMC +0x60000 of the same group, i.e. reg[43] +0x860000, one write-only register
 *     (plain storage here; nothing on this path reads it).
 *  17 (again): +0x28 (0x3028ac028, AppleT8140PMC kind 3, the BOOST interface). The per-device
 *     loop of the slot-0x5a0 routine (0xfffffff0092ab2e8 -> 0xfffffff0092c3f8c ->
 *     0xfffffff0092c41ec) writes each device's PMGR power state and then calls
 *     ApplePMC::stateChange(enable = 1, device id, die) through PMC vtable slot 8
 *     (0xfffffff0092c4238); the base stateChange (0xfffffff0092e4160) runs one handler per
 *     bit of the PMC flags (this+0x24 = 0x3f): bit 0 VOTER (0xfffffff0092e3dd0, kind 0
 *     vote registers, only for dynamic voter agents whose id matches), bit 1 BOOST
 *     (0xfffffff0092e42e0), bit 2 DVMR (0xfffffff0092e43ec), bit 3 BWR (0xfffffff0092e44e4,
 *     kind 1), bit 5 LTR (0xfffffff0092e45f8). The BOOST handler is, for a device id whose
 *     map entry (this+0x106ec + 2 * id) is not -1, a read-modify-write of 0xac028: set
 *     (enable) or clear the bit given by byte 2 of the device's 24-byte record at
 *     [this+0x98]. No poll. The guest's first stateChange that reached a register had
 *     device id 0x3a (MEASURED: saved x22 in the faulting frame).
 *  17 (third time): +0x20 (0x3028ac020, AppleT8140PMC kind 1, the BWR interface). The BWR
 *     handler of stateChange (bit 3, 0xfffffff0092e44e4) scans the BWR table at [this+0x88]
 *     (24-byte records, count [this+0x90]) for records whose u32 at +4 equals
 *     (device id | die << 28); each match is a read-modify-write of 0xac020 setting
 *     (enable) or clearing the bit in record byte 2, through the same T8140PMC kind
 *     thunks. No poll. The sixth stateChange call of the guest reached it (MEASURED:
 *     breakpoints on the handlers, 5 calls passed without a match and the sixth
 *     stopped on this read; the rejection was invisible to -d invalid_mem because the
 *     address lies inside the window, see announce_reject).
 *     NOT listed, deliberately: the LTR handler (bit 5, 0xfffffff0092e45f8) read-modify-writes
 *     +0xa9c18 and then POLLS +0xa9c1c for (reg & mask) == (enable ? mask : 0), an ack bit
 *     that zero storage would never set; it needs a behavioural model, not storage. The
 *     T8140 wrapper's +0x78000 write (devices 0x153..0x157) is not listed either.
 *  19: the DVMR state register +0xa4000 and its busy flag +0xa4020 of the same PMC group
 *     (reg[43] +0x8a4000 and +0x8a4020; window 0x24 bytes with those two registers listed).
 *     ApplePMC::stateChange's DVMR handler (bit 2, 0xfffffff0092e43ec) reads the state
 *     register through PMC vtable slot 0x90 (AppleT8140PMC::readPMCStateReg,
 *     0xfffffff00984ce14: always 0xa4000, whatever the interface argument), sets or clears
 *     the device's bit and writes it back through slot 0x98 (writePMCStateReg,
 *     0xfffffff00984ce4c), which then POLLS 0xa4020 until bit 0 is clear (waitReg32,
 *     offset 0xa4020, mask 1, value 0, timeout 0x2ee00), reads 0xa4000 again and writes
 *     its population count to +0xa9c14. THE POLL: it passes on the first read only
 *     because bit 0 of 0xa4020 is never set (declared: busy never asserted; a driver or
 *     firmware that set it would hang until the timeout).
 *  20: the population-count destination +0xa9c14 (reg[43] +0x8a9c14), write-only here.
 *  21: PMGR_SOC_PWRGATE +0xc8c and +0xcd0 (reg 22, RegMap selector 0x65, physical
 *     0x300724c8c and 0x300724cd0), write-only here. The tail of the T8140 write32 override
 *     (0xfffffff00984b768) consults a second static table at 0xfffffff00b925950 (24-byte
 *     records: trigger selector and offset, target selector and offset, two values; the
 *     two records both trigger on PMGR_SOC +0x10000). When the check at 0xfffffff00984bab4
 *     returns 1 it polls the written register for (v & 0xf0) == 0xf0 and then (v & 0x800) == 0
 *     (generic wait 0xfffffff0092afba0, timeout 0x2ee00; both are reads of the modelled
 *     PMGR_SOC power cell, MEASURED to pass) and calls 0xfffffff00984bbb0 with flag 1, which
 *     does two plain writes through the base vtable slot 0xd30: PwrGate +0xc8c = 0 then
 *     +0xcd0 = 1 (flag 0 writes 3 and 0). Nothing reads them back on this path.
 *     The guest's first rejected access was the +0xc8c write (MEASURED: 0x300724c8c, the
 *     value 0, selector 0x65 in the faulting frame).
 *  22: PMGR_SOC_TVM (reg 25, RegMap selector 0x67, physical 0x300760000) +0x400 and +0x7e0.
 *     The perf-domain routine at 0xfffffff0092b5670 (reached from the slot-0x5a0 routine's
 *     helper 0xfffffff0092ab0b8 through vtable slot 0xc18) calls AppleT8140PMGR's
 *     setTVMEnable (vtable slot 0xa50, 0xfffffff009849284) with enable 0 and wait 1 for every
 *     /arm-io/pmgr soc-clusters record (ADT, 28 bytes: id, flags in byte 2, TVM index in
 *     byte 0xb, name at +0xc) whose flags bit 2 is set and whose TVM index is not 4 or 5. In the
 *     stock ADT only the AVE record (flags 5, index 0xb) qualifies (the plan builder checks
 *     that). setTVMEnable maps index 0xb to control register +0x400 and status register
 *     +0x7e0: read-modify-write (v & ~1) | enable, then, because wait is set and enable
 *     is clear, a POLL of +0x7e0 until bit 1 is clear (readPMGRSOCTVMReg stubs at
 *     0xfffffff00984ebb0 / 0xfffffff00984ec20). THE POLL passes on the first read only because
 *     bit 1 of +0x7e0 is never set (declared: the TVM never reports busy). The other TVM
 *     indices (1: +0x0/+0x3e0, 2: +0xc00/+0xfe0, 6: +0x800/+0xbe0, 9: +0x1000/+0x13e0) are
 *     NOT listed: no soc-clusters record selects them. The guest's first rejected access was
 *     the +0x400 read (MEASURED: 0x300760400, selector 0x67).
 *  23-32: ten block-local register pairs the T8140 PS-write hook read-modify-writes. The
 *     AppleT8140PMGR write32 override (vtable slot 0xd20, 0xfffffff00984b768; ApplePMGR's
 *     PS-level writer 0xfffffff00929fe20 calls it) runs when this+0x738f0 is non-zero
 *     (0x3ff, MEASURED in the guest: all ten entries enabled). It searches the static table
 *     at 0xfffffff00b9257c0 (ten 40-byte entries: u32 RegMap selector 0, u32 PMGR_SOC
 *     register offset, u64 physical block base, two runtime pointers) for the written
 *     (selector, offset); a match calls the check function 0xfffffff00984b2b0, which
 *     sets bit 0 of the registers at base + 0x104 and base + 0x108 (power-up, 0x984b384)
 *     or clears it (power-down, 0x984b3c4), each a plain read-modify-write through a
 *     pointer mapped at init (0xfffffff00984760c: IOMemoryDescriptor on base + 0x104 and
 *     base + 0x108, length 4). The mask-driven loop at 0xfffffff009848214 calls the same
 *     function for every entry whose PMGR_SOC register reads actual state 0xf. No poll.
 *     The entries (PMGR_SOC offset, block base): 0x3e8 0x408000000, 0x280 0x413000000,
 *     0x288 0x417000000, 0x278 0x38b000000 (/arm-io/ans reg[4]), 0x270 0x380000000
 *     (/arm-io/avd reg[0]), 0x240 0x284000000 (/arm-io/ave reg[4]), 0x248 0x288000000
 *     (/arm-io/ave1 reg[4]), 0x1f0 0x481000000 (/arm-io/sgx reg[0] +0x1000000), 0x230
 *     0x28c000000, 0x2a0 0x396000000 (/arm-io/apcie reg[4]). The guest's first rejected
 *     access was entry 1 (MEASURED: 0x413000104, the PMGR_SOC +0x280 write); the other
 *     nine pairs are listed from the table and the measured mask, not from a run. None of
 *     these blocks is otherwise modelled, so only the two registers per block exist.
 */
typedef struct FixedWindow {
    unsigned reg_index;
    uint32_t offset, size;
    unsigned nregs;         /* 0: every 4-byte slot of the window is a register */
    uint16_t regs[8];       /* else: register offsets inside the window (multiples of 4) */
} FixedWindow;
#define DPE_CHANNEL(n) {32, 0x2400 + 0x400 * (n), 0x304, 3, {0, 0x200, 0x300}}
static const FixedWindow fixed_windows[] = {
    {4, 0x8, 0x20, 0, {0}},
    {34, 0x18200, 0x80, 0, {0}},
    {34, 0x18300, 0x80, 0, {0}},
    {34, 0x18400, 0x400, 0, {0}},
    /* Five ADT soc-clusters, indexed 0..4. ApplePMGR 0x92b57b0 computes
     * base + 4*cluster, RMWs the low nibble, then polls bit 4 clear. The
     * retained v14 guest witnesses cluster 2 (+8), caller 0x92b57e8.
     * Zero-reset storage retains the existing immediate/no-busy profile. */
    {28, 0x0, 0x14, 0, {0}},
    {22, 0x0, 0x4, 0, {0}},
    {22, 0x40, 0x4, 0, {0}},
    DPE_CHANNEL(0), DPE_CHANNEL(1), DPE_CHANNEL(2), DPE_CHANNEL(3), DPE_CHANNEL(4),
    DPE_CHANNEL(5), DPE_CHANNEL(6),
    {32, 0x4200, 0x104, 2, {0, 0x100}},     /* channel 7 has no +0x0 register */
    DPE_CHANNEL(8), DPE_CHANNEL(9),
    {43, 0x8ac000, 0x2c, 7, {0, 4, 8, 0xc, 0x20, 0x24, 0x28}},  /* PMC votes 0..3, bwr, dynamic, boost */
    {43, 0x860000, 0x4, 0, {0}},            /* PMC +0x60000 (kRegGroupPMCDVFM + 0x60000) */
    {43, 0x8a4000, 0x24, 2, {0, 0x20}},     /* PMC DVMR state +0xa4000, busy +0xa4020 */
    {43, 0x8a9c14, 0x4, 0, {0}},            /* PMC DVMR popcount +0xa9c14 */
    {22, 0xc8c, 0x48, 2, {0, 0x44}},        /* PwrGate +0xc8c and +0xcd0 (hook table 2) */
    {25, 0x400, 0x3e4, 2, {0, 0x3e0}},      /* PMGR_SOC_TVM index 0xb: control +0x400, status +0x7e0 */
};

/* AppleT8140PMGR slot0xb88 (0x984a4cc) restores ACC accounting
 * counters, NOT power votes. Kinds0/1 have 8/18 qwords at +400/+500;
 * kinds10/11 (bound57) form the union +680..+84f; kinds20/21 add
 * the extended ranges below. Captured at the generic 64-bit store:
 * selector9, offset400, value0, caller0x92aa10c (v23). No event
 * producer is attached; like the other counters these are plain storage.
 * Append after the existing groups/windows to preserve their identities. */
#define ACC_COUNTER_TAG_BASE 0x200
static const FixedWindow acc_counter_windows[] = {
    {5, 0x400, 0x40, 0, {0}}, {5, 0x500, 0x40, 0, {0}},
    {5, 0x680, 0x1d0, 0, {0}}, {5, 0x10e8, 0x40, 0, {0}},
    {5, 0x11e8, 0x40, 0, {0}},
    {14, 0x400, 0x90, 0, {0}}, {14, 0x500, 0x90, 0, {0}},
    {14, 0x680, 0x1d0, 0, {0}}, {14, 0x11e8, 0x90, 0, {0}},
    /* Slotsbc8/bd0: per-core counter pairs9000/9008 (table0x77b2038).
     * CPU0's pair is already inside the board's cpu-impl-reg RAM.
     * Slotsbd8/be0: cluster pair8000/8008; E is already inside cpm-impl
     * RAM. List only the five other cores and the P cluster here. */
    {11, 0x9000, 0x10, 0, {0}}, {12, 0x9000, 0x10, 0, {0}},
    {13, 0x9000, 0x10, 0, {0}}, {19, 0x9000, 0x10, 0, {0}},
    {20, 0x9000, 0x10, 0, {0}}, {16, 0x8000, 0x10, 0, {0}},
};
static const uint64_t acc_counter_banks[] = {
    UINT64_C(0x210e20000), UINT64_C(0x210e20000), UINT64_C(0x210e20000),
    UINT64_C(0x210e20000), UINT64_C(0x210e20000),
    UINT64_C(0x211e20000), UINT64_C(0x211e20000), UINT64_C(0x211e20000),
    UINT64_C(0x211e20000),
    UINT64_C(0x210150000), UINT64_C(0x210250000), UINT64_C(0x210350000),
    UINT64_C(0x211050000), UINT64_C(0x211150000), UINT64_C(0x211e40000),
};
_Static_assert(ARRAY_ENTRIES(acc_counter_banks) == ARRAY_ENTRIES(acc_counter_windows),
               "ACC register windows require matched bank addresses");

/* Block bases of the T8140 PS-write hook table (see item 23-32 above), in table order. The window
 * of block b is the register pair at b + 0x104 and b + 0x108; each must lie inside the /arm-io
 * bus ranges. Their tags continue the fixed windows' (FIXED_TAG_BASE + count + index). */
#define ACG_OFFSET 0x104
#define ACG_SIZE 0x8
static const uint64_t acg_blocks[] = {
    UINT64_C(0x408000000), UINT64_C(0x413000000), UINT64_C(0x417000000), UINT64_C(0x38b000000),
    UINT64_C(0x380000000), UINT64_C(0x284000000), UINT64_C(0x288000000), UINT64_C(0x481000000),
    UINT64_C(0x28c000000), UINT64_C(0x396000000),
};

/* Append one window after the geometry checks; *plan is unchanged on failure. */
static bool place(AppleModernPMGRStoragePlan *plan, uint64_t address, uint32_t size,
                  uint32_t tag, const uint64_t *valid, uint64_t dram_base,
                  uint64_t dram_size, const AppleModernAddressRange *exclusions,
                  size_t exclusion_count, Error **errp)
{
    AppleModernPMGRStorageWindow *w;
    if (plan->count == APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS) {
        error_setg(errp, "too many PMGR storage windows");
        return false;
    }
    if (!size || size > APPLE_MODERN_PMGR_STORAGE_MAX_SPAN || address > UINT64_MAX - size ||
        overlaps(address, size, dram_base, dram_size)) {
        error_setg(errp, "PMGR storage window %u is empty, too large, wraps or overlaps DRAM",
                   tag);
        return false;
    }
    for (size_t k = 0; k < exclusion_count; k++) {
        if (overlaps(address, size, exclusions[k].physical_address, exclusions[k].size)) {
            error_setg(errp, "PMGR storage window %u overlaps another device", tag);
            return false;
        }
    }
    for (unsigned k = 0; k < plan->count; k++) {
        if (overlaps(address, size, plan->windows[k].address, plan->windows[k].size)) {
            error_setg(errp, "PMGR storage windows %u and %u overlap",
                       plan->windows[k].group, tag);
            return false;
        }
    }
    w = &plan->windows[plan->count++];
    w->address = address;
    w->size = size;
    w->group = tag;
    memcpy(w->valid, valid, sizeof(w->valid));
    for (unsigned k = 0; k < APPLE_MODERN_PMGR_STORAGE_MASKS; k++) {
        plan->registers += __builtin_popcountll(w->valid[k]);
    }
    return true;
}

bool apple_modern_pmgr_storage_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernPMGRStoragePlan *output, Error **errp)
{
    AppleModernBlob reg, groups_blob, counters, ranges, rails, clusters;
    Group groups[MAX_GROUPS];
    AppleModernPMGRStoragePlan plan;
    unsigned group_count, counter_count;
    if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||
        exclusion_count > APPLE_MODERN_MAX_BOARD_EXCLUSIONS ||
        (exclusion_count && !exclusions) ||
        (exclusions && aliases(output, sizeof(*output), exclusions,
                               exclusion_count * sizeof(*exclusions)))) {
        error_setg(errp, "PMGR storage output aliases input or exclusions are invalid");
        return false;
    }
    memset(output, 0, sizeof(*output));
    memset(&plan, 0, sizeof(plan));
    if (!dram_size || dram_size > UINT64_MAX - dram_base) {
        error_setg(errp, "PMGR storage DRAM extent is empty or wraps");
        return false;
    }
    for (size_t i = 0; i < exclusion_count; i++) {
        if (!exclusions[i].size || exclusions[i].size >
                UINT64_MAX - exclusions[i].physical_address) {
            error_setg(errp, "PMGR storage exclusion is empty or wraps");
            return false;
        }
    }
    if (!apple_modern_adt_property(tree, "/arm-io/pmgr", "reg", &reg, errp) ||
        !apple_modern_adt_property(tree, "/arm-io/pmgr", "perf-groups", &groups_blob, errp) ||
        !apple_modern_adt_property(tree, "/arm-io/pmgr", "perf-counters", &counters, errp) ||
        !apple_modern_adt_property(tree, "/arm-io", "ranges", &ranges, errp)) {
        return false;
    }
    if (!apple_modern_adt_property(tree, "/arm-io/pmgr", "voter-rail-data", &rails, errp)) {
        return false;
    }
    /* The vote-register window lists exactly rails 0..3 (24-byte records, u16 rail index first). */
    if (rails.size != VOTER_RAILS * VOTER_RAIL_RECORD) {
        error_setg(errp, "unsupported PMGR voter-rail-data schema");
        return false;
    }
    for (unsigned i = 0; i < VOTER_RAILS; i++) {
        if (rails.data[VOTER_RAIL_RECORD * i] != i || rails.data[VOTER_RAIL_RECORD * i + 1]) {
            error_setg(errp, "PMGR voter rail %u has an index the vote-register window does not list", i);
            return false;
        }
    }
    /* Only the AVE record (index 2) selects a TVM, with index 0xb: that is what the TVM window lists. */
    if (!apple_modern_adt_property(tree, "/arm-io/pmgr", "soc-clusters", &clusters, errp)) {
        return false;
    }
    if (clusters.size != SOC_CLUSTERS * SOC_CLUSTER_RECORD) {
        error_setg(errp, "unsupported PMGR soc-clusters schema");
        return false;
    }
    for (unsigned i = 0; i < SOC_CLUSTERS; i++) {
        const uint8_t *c = clusters.data + SOC_CLUSTER_RECORD * i;
        if (c[0] != i) {
            error_setg(errp, "PMGR cluster-control profile requires cluster ids 0..4");
            return false;
        }
        bool selects = (c[2] & 4) && (c[0xb] & 0xfe) != 4;
        if (selects != (i == SOC_CLUSTER_AVE) || (selects && c[0xb] != 0xb)) {
            error_setg(errp, "PMGR soc-clusters record %u selects a TVM the window does not list", i);
            return false;
        }
    }
    if (!reg.size || reg.size % 16 || reg.size > MAX_REG_ENTRIES * 16 ||
        !groups_blob.size || groups_blob.size % GROUP_RECORD ||
        groups_blob.size > MAX_GROUPS * GROUP_RECORD ||
        !counters.size || counters.size % COUNTER_RECORD ||
        counters.size > MAX_COUNTERS * COUNTER_RECORD ||
        !ranges.size || ranges.size % 24) {
        error_setg(errp, "unsupported PMGR perf-groups/perf-counters/reg schema");
        return false;
    }
    group_count = groups_blob.size / GROUP_RECORD;
    counter_count = counters.size / COUNTER_RECORD;
    memset(groups, 0, sizeof(groups));
    for (unsigned i = 0; i < group_count; i++) {
        const uint8_t *r = groups_blob.data + GROUP_RECORD * i;
        groups[i].reg_index = le32(r);
        groups[i].base = le32(r + 4);
        groups[i].flags = le32(r + 8);
        if (groups[i].reg_index >= reg.size / 16) {
            error_setg(errp, "PMGR perf group %u names a missing reg window", i);
            return false;
        }
    }
    /* Group controls, also used by the later counter-enable routine. */
    for (unsigned i = 0; i < group_count; i++) {
        if (!mark(groups, group_count, reg, i, 0, errp)) {
            return false;
        }
    }
    /* init programming plus the later enable loop at 0x92b84d0. For each
     * non-event counter, 0x92cadb0 writes two 32-bit data words at
     * group.base + counter.offset + group.data_offset, then +4. T8140's
     * original ADT names the registers; v15 measures group1+0x110 first.
     * They remain declared zero-reset storage, without counting events. */
    for (unsigned i = 0; i < counter_count; i++) {
        const uint8_t *c = counters.data + COUNTER_RECORD * i;
        unsigned type = c[0], group = c[4];
        if (group >= group_count) {
            error_setg(errp, "PMGR perf counter %u names group %u of %u", i, group,
                       group_count);
            return false;
        }
        if (type == 3) {
            continue;
        }
        if (type > 4) {
            error_setg(errp, "PMGR perf counter %u has type %u, which panics the driver",
                       i, type);
            return false;
        }
        uint64_t offset = le32(c + 8);
        uint64_t data_offset = le32(groups_blob.data + GROUP_RECORD * group + 12);
        if (!mark(groups, group_count, reg, group, offset, errp) ||
            !mark(groups, group_count, reg, group, offset + data_offset, errp) ||
            !mark(groups, group_count, reg, group, offset + data_offset + 4, errp)) {
            return false;
        }
        /* Initialization uses flag bit1; the later enable path at
         * 0x92b85dc also writes the second data value for flags==1. */
        if (type == 1 && ((c[1] & 2) || c[1] == 1)) {
            unsigned second = c[5];
            if (second >= group_count) {
                error_setg(errp, "PMGR secondary counter group is missing");
                return false;
            }
            offset = le32(c + 12);
            data_offset = le32(groups_blob.data + GROUP_RECORD * second + 12);
            if (!mark(groups, group_count, reg, second, offset, errp) ||
                !mark(groups, group_count, reg, second, offset + data_offset, errp) ||
                !mark(groups, group_count, reg, second, offset + data_offset + 4, errp)) {
                return false;
            }
        }
    }
    for (unsigned i = 0; i < group_count; i++) {
        uint64_t base;
        if (!(groups[i].flags & GROUP_PROGRAMMED)) {
            continue;
        }
        if (!translate(ranges, le64(reg.data + 16 * groups[i].reg_index),
                       le64(reg.data + 16 * groups[i].reg_index + 8), &base) ||
            base > UINT64_MAX - groups[i].base) {
            error_setg(errp, "PMGR perf group %u is outside the /arm-io bus ranges", i);
            return false;
        }
        if (!place(&plan, base + groups[i].base, groups[i].end, i, groups[i].valid,
                   dram_base, dram_size, exclusions, exclusion_count, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < ARRAY_ENTRIES(fixed_windows); i++) {
        const FixedWindow *f = &fixed_windows[i];
        uint64_t valid[APPLE_MODERN_PMGR_STORAGE_MASKS] = {0};
        uint64_t base, reg_size;
        if (f->reg_index >= reg.size / 16) {
            error_setg(errp, "PMGR fixed window %u names a missing reg window", i);
            return false;
        }
        reg_size = le64(reg.data + 16 * f->reg_index + 8);
        if (f->offset > reg_size || reg_size - f->offset < f->size ||
            !translate(ranges, le64(reg.data + 16 * f->reg_index), reg_size, &base) ||
            base > UINT64_MAX - f->offset) {
            error_setg(errp, "PMGR fixed window %u is outside its reg window or the "
                       "/arm-io bus ranges", i);
            return false;
        }
        if (f->nregs) {
            for (unsigned r = 0; r < f->nregs; r++) {
                valid[f->regs[r] / 4 / 64] |= UINT64_C(1) << ((f->regs[r] / 4) % 64);
            }
        } else {
            for (unsigned slot = 0; slot < f->size / 4; slot++) {
                valid[slot / 64] |= UINT64_C(1) << (slot % 64);
            }
        }
        if (!place(&plan, base + f->offset, f->size, FIXED_TAG_BASE + i, valid,
                   dram_base, dram_size, exclusions, exclusion_count, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < ARRAY_ENTRIES(acg_blocks); i++) {
        uint64_t valid[APPLE_MODERN_PMGR_STORAGE_MASKS] = {0};
        for (unsigned slot = 0; slot < ACG_SIZE / 4; slot++) {
            valid[slot / 64] |= UINT64_C(1) << (slot % 64);
        }
        if (!physical_in_ranges(ranges, acg_blocks[i] + ACG_OFFSET, ACG_SIZE)) {
            error_setg(errp, "PMGR block-local register pair %u is outside the /arm-io bus ranges", i);
            return false;
        }
        if (!place(&plan, acg_blocks[i] + ACG_OFFSET, ACG_SIZE,
                   FIXED_TAG_BASE + ARRAY_ENTRIES(fixed_windows) + i, valid,
                   dram_base, dram_size, exclusions, exclusion_count, errp)) {
            return false;
        }
    }
    /* Keep the prior programmed-group/fixed-window identities stable and
     * append the other ADT counter groups. Accept no unlisted holes. */
    for (unsigned i = 0; i < group_count; i++) {
        uint64_t base;
        if (groups[i].flags & GROUP_PROGRAMMED) {
            continue;
        }
        if (!translate(ranges, le64(reg.data + 16 * groups[i].reg_index),
                       le64(reg.data + 16 * groups[i].reg_index + 8), &base) ||
            base > UINT64_MAX - groups[i].base) {
            error_setg(errp, "PMGR counter group translation failed");
            return false;
        }
        if (!place(&plan, base + groups[i].base, groups[i].end, i, groups[i].valid,
                   dram_base, dram_size, exclusions, exclusion_count, errp)) {
            return false;
        }
    }
    for (unsigned i = 0; i < ARRAY_ENTRIES(acc_counter_windows); i++) {
        const FixedWindow *f = &acc_counter_windows[i];
        uint64_t base, valid[APPLE_MODERN_PMGR_STORAGE_MASKS] = {0};
        uint64_t size = le64(reg.data + 16 * f->reg_index + 8);
        uint64_t expected = acc_counter_banks[i];
        if (size < f->offset + f->size ||
            !translate(ranges, le64(reg.data + 16 * f->reg_index), size, &base) ||
            base != expected) {
            error_setg(errp, "ACC accounting-counter range is outside matched PWRCTL");
            return false;
        }
        for (unsigned word = 0; word < f->size / 4; word++) {
            valid[word / 64] |= UINT64_C(1) << (word % 64);
        }
        if (!place(&plan, base + f->offset, f->size, ACC_COUNTER_TAG_BASE + i,
                   valid, dram_base, dram_size, exclusions, exclusion_count, errp)) {
            return false;
        }
    }
    *output = plan;
    return true;
}

static void increment(uint64_t *value)
{
    if (*value != UINT64_MAX) {
        (*value)++;
    }
}

void apple_modern_pmgr_storage_core_reset(AppleModernPMGRStorageCore *core)
{
    memset(core->values, 0, sizeof(core->values));
    memset(core->touched, 0, sizeof(core->touched));
    core->reads = core->writes = 0;
}

static bool slot_valid(const AppleModernPMGRStorageWindow *w, uint64_t slot)
{
    return slot < w->size / 4 && (w->valid[slot / 64] >> (slot % 64)) & 1;
}

/* All covered slots of a natural 4- or 8-byte access are listed registers. */
static bool valid_access(const AppleModernPMGRStorageCore *core, unsigned window,
                         uint64_t offset, unsigned size)
{
    if (window >= core->plan.count || (size != 4 && size != 8) || (offset & (size - 1)) ||
        offset >= core->plan.windows[window].size) {
        return false;
    }
    for (unsigned s = 0; s < size / 4; s++) {
        if (!slot_valid(&core->plan.windows[window], offset / 4 + s)) {
            return false;
        }
    }
    return true;
}

static void touch(AppleModernPMGRStorageCore *core, unsigned window, uint64_t offset,
                  unsigned size)
{
    for (unsigned s = 0; s < size / 4; s++) {
        uint64_t slot = offset / 4 + s;
        core->touched[window][slot / 64] |= UINT64_C(1) << (slot % 64);
    }
}

bool apple_modern_pmgr_storage_core_touched(const AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset)
{
    return core && window < core->plan.count &&
           slot_valid(&core->plan.windows[window], offset / 4) &&
           (core->touched[window][offset / 4 / 64] >> ((offset / 4) % 64)) & 1;
}

bool apple_modern_pmgr_storage_core_read(AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t *value)
{
    if (!core || !value || !valid_access(core, window, offset, size) ||
        aliases(core, sizeof(*core), value, sizeof(*value))) {
        return false;
    }
    uint64_t slot = offset / 4;
    *value = core->values[window][slot];
    if (size == 8) {
        *value |= (uint64_t)core->values[window][slot + 1] << 32;
    }
    touch(core, window, offset, size);
    increment(&core->reads);
    return true;
}

bool apple_modern_pmgr_storage_core_write(AppleModernPMGRStorageCore *core,
    unsigned window, uint64_t offset, unsigned size, uint64_t value)
{
    if (!core || !valid_access(core, window, offset, size)) {
        return false;
    }
    uint64_t slot = offset / 4;
    core->values[window][slot] = (uint32_t)value;
    if (size == 8) {
        core->values[window][slot + 1] = (uint32_t)(value >> 32);
    }
    touch(core, window, offset, size);
    increment(&core->writes);
    return true;
}

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
typedef struct StorageView {
    AppleModernPMGRStorageCore *core;
    unsigned index;
    uint64_t *rejected;     /* diagnostics only: one bit per 4-byte slot already announced */
} StorageView;
struct AppleModernPMGRStorageState {
    SysBusDevice parent_obj;
    bool mapped;
    bool permissive;
    uint32_t ltr_shadow;
    AppleModernPMGRStorageCore core;
    StorageView views[APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS];
    MemoryRegion regions[APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS];
    uint64_t rejected[APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS][APPLE_MODERN_PMGR_STORAGE_MASKS];
};
/* A rejected access INSIDE a window (a hole between listed registers, a size or alignment the
 * window does not take) is not logged by -d invalid_mem, which only reports unmapped addresses.
 * Announce the first one per 4-byte slot so a run shows the next unmodelled register. */
static void announce_reject(StorageView *view, hwaddr offset, unsigned size, const char *what)
{
    uint64_t slot = offset / 4;
    if (slot < APPLE_MODERN_PMGR_STORAGE_SLOTS &&
        !((view->rejected[slot / 64] >> (slot % 64)) & 1)) {
        view->rejected[slot / 64] |= UINT64_C(1) << (slot % 64);
        info_report("apple-modern pmgr-storage: REJECTED %s of window %u (group %u) +0x%"
                    HWADDR_PRIx " (%u bytes, address 0x%" PRIx64 ")", what, view->index,
                    view->core->plan.windows[view->index].group, offset, size,
                    view->core->plan.windows[view->index].address + offset);
    }
}
/* A register is announced once, on its first successful access (at most one line
 * per listed register), so a run shows exactly which registers the guest touched. */
static void announce(StorageView *view, bool fresh, hwaddr offset, unsigned size,
                     const char *what)
{
    if (fresh) {
        info_report("apple-modern pmgr-storage: first %s of window %u (group %u) +0x%"
                    HWADDR_PRIx " (%u bytes)", what, view->index,
                    view->core->plan.windows[view->index].group, offset, size);
    }
}
static MemTxResult storage_read(void *opaque, hwaddr offset, uint64_t *value,
                                unsigned size, MemTxAttrs attrs)
{
    StorageView *view = opaque;
    AppleModernPMGRStorageState *s = container_of(view->core,
                                                  AppleModernPMGRStorageState, core);
    bool fresh = !apple_modern_pmgr_storage_core_touched(view->core, view->index, offset);
    if (!apple_modern_pmgr_storage_core_read(view->core, view->index, offset, size,
                                             value)) {
        announce_reject(view, offset, size, "read");
        if (s->permissive && (size == 4 || size == 8) && !(offset & (size - 1)) &&
            offset + size <= APPLE_MODERN_PMGR_STORAGE_MAX_SPAN) {
            uint64_t phys = view->core->plan.windows[view->index].address + offset;
            uint64_t slot = offset / 4;
            if (phys == UINT64_C(0x3028a9c1c)) {
                *value = s->ltr_shadow;
            } else {
                *value = view->core->values[view->index][slot];
                if (size == 8) {
                    *value |= (uint64_t)view->core->values[view->index][slot + 1] << 32;
                }
            }
            return MEMTX_OK;
        }
        return MEMTX_ACCESS_ERROR;
    }
    announce(view, fresh, offset, size, "read");
    return MEMTX_OK;
}
static MemTxResult storage_write(void *opaque, hwaddr offset, uint64_t value,
                                 unsigned size, MemTxAttrs attrs)
{
    StorageView *view = opaque;
    AppleModernPMGRStorageState *s = container_of(view->core,
                                                  AppleModernPMGRStorageState, core);
    bool fresh = !apple_modern_pmgr_storage_core_touched(view->core, view->index, offset);
    if (!apple_modern_pmgr_storage_core_write(view->core, view->index, offset, size,
                                              value)) {
        announce_reject(view, offset, size, "write");
        if (s->permissive && (size == 4 || size == 8) && !(offset & (size - 1)) &&
            offset + size <= APPLE_MODERN_PMGR_STORAGE_MAX_SPAN) {
            uint64_t phys = view->core->plan.windows[view->index].address + offset;
            uint64_t slot = offset / 4;
            view->core->values[view->index][slot] = (uint32_t)value;
            if (size == 8) {
                view->core->values[view->index][slot + 1] = (uint32_t)(value >> 32);
            }
            if (phys == UINT64_C(0x3028a9c18)) {
                s->ltr_shadow = (uint32_t)value;
            }
            return MEMTX_OK;
        }
        return MEMTX_ACCESS_ERROR;
    }
    announce(view, fresh, offset, size, "write");
    return MEMTX_OK;
}
static const MemoryRegionOps storage_ops = {
    .read_with_attrs = storage_read, .write_with_attrs = storage_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 8, .unaligned = false},
    .impl = {.min_access_size = 4, .max_access_size = 8},
};
static void storage_reset(DeviceState *dev)
{
    AppleModernPMGRStorageState *s = APPLE_MODERN_PMGR_STORAGE(dev);
    apple_modern_pmgr_storage_core_reset(&s->core);
    s->ltr_shadow = 0;
    memset(s->rejected, 0, sizeof(s->rejected));
}
static bool get_permissive(Object *obj, Error **errp)
{
    return APPLE_MODERN_PMGR_STORAGE(obj)->permissive;
}
static void set_permissive(Object *obj, bool value, Error **errp)
{
    APPLE_MODERN_PMGR_STORAGE(obj)->permissive = value;
}
static void storage_realize(DeviceState *dev, Error **errp)
{
    AppleModernPMGRStorageState *s = APPLE_MODERN_PMGR_STORAGE(dev);
    if (!s->core.plan.count || s->core.plan.count > APPLE_MODERN_PMGR_STORAGE_MAX_WINDOWS) {
        error_setg(errp, "invalid PMGR storage window count");
        return;
    }
    for (unsigned i = 0; i < s->core.plan.count; i++) {
        char name[48];
        s->views[i] = (StorageView){&s->core, i, s->rejected[i]};
        snprintf(name, sizeof(name), "apple-modern.pmgr-storage-%u",
                 s->core.plan.windows[i].group);
        memory_region_init_io(&s->regions[i], OBJECT(dev), &storage_ops, &s->views[i],
                              name, s->core.plan.windows[i].size);
    }
}
bool apple_modern_pmgr_storage_map(DeviceState *dev, MemoryRegion *memory,
                                   Error **errp)
{
    AppleModernPMGRStorageState *s = APPLE_MODERN_PMGR_STORAGE(dev);
    if (!dev->realized || s->mapped || !memory) {
        error_setg(errp, "PMGR storage must be realized and mapped exactly once");
        return false;
    }
    /* A valid plan can contain more than QDEV_MAX_MMIO (32) windows. Calling
     * sysbus_init_mmio for each used to overrun its fixed array in NDEBUG
     * builds. Map only these validated, disjoint ranges, not a catch-all. */
    for (unsigned i = 0; i < s->core.plan.count; i++) {
        memory_region_add_subregion(memory, s->core.plan.windows[i].address,
                                    &s->regions[i]);
    }
    s->mapped = true;
    return true;
}
static void get_mapping_counter(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    AppleModernPMGRStorageState *s = APPLE_MODERN_PMGR_STORAGE(obj);
    uint64_t value = opaque ? SYS_BUS_DEVICE(s)->num_mmio :
                             (s->mapped ? s->core.plan.count : 0);
    visit_type_uint64(v, name, &value, errp);
}
static void get_counter(Object *obj, Visitor *v, const char *name, void *opaque,
                        Error **errp)
{
    AppleModernPMGRStorageCore *core = &APPLE_MODERN_PMGR_STORAGE(obj)->core;
    uint64_t value = *(uint64_t *)((uint8_t *)core + (uintptr_t)opaque);
    visit_type_uint64(v, name, &value, errp);
}
static const VMStateDescription storage_unmigratable = {
    .name = TYPE_APPLE_MODERN_PMGR_STORAGE, .unmigratable = 1,
};
static void storage_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = storage_realize;
    dc->vmsd = &storage_unmigratable;
    dc->user_creatable = false;
    device_class_set_legacy_reset(dc, storage_reset);
    object_class_property_add(oc, "mmio-read-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernPMGRStorageCore, reads));
    object_class_property_add(oc, "mmio-write-count", "uint64", get_counter, NULL, NULL,
        (void *)offsetof(AppleModernPMGRStorageCore, writes));
    object_class_property_add(oc, "mapped-window-count", "uint64", get_mapping_counter,
                              NULL, NULL, NULL);
    object_class_property_add(oc, "sysbus-mmio-count", "uint64", get_mapping_counter,
                              NULL, NULL, (void *)1);
    object_class_property_add_bool(oc, "permissive", get_permissive, set_permissive);
}
DeviceState *apple_modern_pmgr_storage_new(const AppleModernPMGRStoragePlan *plan)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_PMGR_STORAGE);
    APPLE_MODERN_PMGR_STORAGE(dev)->core.plan = *plan;
    storage_reset(dev);
    return dev;
}
static const TypeInfo storage_type = {
    .name = TYPE_APPLE_MODERN_PMGR_STORAGE, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernPMGRStorageState), .class_init = storage_class_init,
};
static void register_types(void) { type_register_static(&storage_type); }
type_init(register_types)
#endif
