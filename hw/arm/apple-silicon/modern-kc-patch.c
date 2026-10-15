/*
 * Declared kernel-cache compatibility shim for the modern boot experiment.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Port of qemu-sptm 2867d847 hw/arm/xnu_patch.c patch_img4_deadlock(), adapted
 * to Inferno's bounded-parsing style. See modern-kc-patch.h for the rationale:
 * it lets unmodified firmware proceed past the AppleImage4 ignition-blob sysctl
 * handler when the board models no ignition/SEP infrastructure. Opt-in; applied
 * only to the board's private in-memory kernel-cache copy; fully bounds-checked.
 */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
/* Test adapter only; production uses QEMU's osdep/bswap/Error. */
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#include "qemu/bswap.h"
#endif
#include "hw/arm/apple-silicon/modern-kc-patch.h"

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
static void error_setg(Error **errp, const char *format, ...)
{
    va_list args;
    if (!errp) {
        return;
    }
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

static uint32_t ldl_le_p(const void *p)
{
    const uint8_t *b = p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint64_t ldq_le_p(const void *p)
{
    const uint8_t *b = p;
    return (uint64_t)ldl_le_p(b) | ((uint64_t)ldl_le_p(b + 4) << 32);
}

static void stl_le_p(void *p, uint32_t v)
{
    uint8_t *b = p;
    b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24;
}
#endif

#define MH_MAGIC_64         0xfeedfacfu
#define LC_SEGMENT_64       0x19u
#define LC_FILESET_ENTRY    0x80000035u
#define SEG_CMD_MIN         72u
#define SECTION_64_SIZE     80u

/* Instructions (little-endian words). */
#define INSN_PACIBSP        0xd503237fu
#define INSN_BTI_C          0xd503245fu
#define INSN_MOVZ_X0_0      0xd2800000u /* movz x0, #0 */
#define INSN_RETAB          0xd65f0fffu

/*
 * Kernel-cache dyld-chained rebase pointers keep the in-cache target in their
 * low 30 bits (DYLD_CHAINED_PTR_64_KERNEL_CACHE); the rest is fixup metadata.
 */
#define KC_FIXUP_TARGET_MASK ((UINT64_C(1) << 30) - 1)

/* sysctl_oid (xnu LP64): oid_name at +40, oid_handler at +48. */
#define OID_NAME_OFFSET     40u
#define OID_HANDLER_OFFSET  48u

static bool rd32(const uint8_t *buf, size_t len, uint64_t off, uint32_t *out)
{
    if (off > len - 4) {
        return false;
    }
    *out = ldl_le_p(buf + off);
    return true;
}

static bool rd64(const uint8_t *buf, size_t len, uint64_t off, uint64_t *out)
{
    if (off > len - 8) {
        return false;
    }
    *out = ldq_le_p(buf + off);
    return true;
}

/*
 * Locate one segment and, optionally, one of its sections in the Mach-O whose
 * header sits at image_base. Section offsets in a kernel-cache fileset are
 * global to the whole boot kernel cache. Returns false if absent or malformed.
 */
static bool find_segment(const uint8_t *buf, size_t len, uint64_t image_base,
                         const char *seg, const char *sect,
                         uint64_t *out_off, uint64_t *out_size)
{
    uint32_t magic, ncmds;
    uint64_t cursor;

    if (!rd32(buf, len, image_base, &magic) || magic != MH_MAGIC_64 ||
        !rd32(buf, len, image_base + 16, &ncmds)) {
        return false;
    }
    if (ncmds > 4096) {
        return false;
    }
    cursor = image_base + 32;
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd, cmdsize;

        if (!rd32(buf, len, cursor, &cmd) ||
            !rd32(buf, len, cursor + 4, &cmdsize) ||
            cmdsize < 8 || cmdsize > len - cursor) {
            return false;
        }
        size_t seglen = strlen(seg);
        if (cmd == LC_SEGMENT_64 && cmdsize >= SEG_CMD_MIN && seglen < 16 &&
            !memcmp(buf + cursor + 8, seg, seglen) &&
            buf[cursor + 8 + seglen] == '\0') {
            uint64_t fileoff, filesize;
            uint32_t nsects;

            if (!rd64(buf, len, cursor + 40, &fileoff) ||
                !rd64(buf, len, cursor + 48, &filesize) ||
                !rd32(buf, len, cursor + 64, &nsects)) {
                return false;
            }
            if (!sect) {
                *out_off = fileoff;
                *out_size = filesize;
                return true;
            }
            if (nsects > (cmdsize - SEG_CMD_MIN) / SECTION_64_SIZE) {
                return false;
            }
            for (uint32_t s = 0; s < nsects; s++) {
                uint64_t so = cursor + SEG_CMD_MIN + (uint64_t)s * SECTION_64_SIZE;
                uint64_t ssize;
                uint32_t soff;

                if (so + 48 > len || buf[so + 16 + 15] != '\0' ||
                    strcmp((const char *)(buf + so), sect) != 0) {
                    continue;
                }
                if (!rd64(buf, len, so + 40, &ssize) ||
                    !rd32(buf, len, so + 48, &soff)) {
                    return false;
                }
                *out_off = soff;
                *out_size = ssize;
                return true;
            }
            return false;
        }
        cursor += cmdsize;
    }
    return false;
}

static bool find_fileset_entry(const uint8_t *buf, size_t len,
                               const char *name, uint64_t *out_fileoff)
{
    uint32_t magic, ncmds;
    uint64_t cursor;

    if (!rd32(buf, len, 0, &magic) || magic != MH_MAGIC_64 ||
        !rd32(buf, len, 16, &ncmds) || ncmds > 4096) {
        return false;
    }
    cursor = 32;
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd, cmdsize, name_off;
        uint64_t fileoff;

        if (!rd32(buf, len, cursor, &cmd) ||
            !rd32(buf, len, cursor + 4, &cmdsize) ||
            cmdsize < 8 || cmdsize > len - cursor) {
            return false;
        }
        if (cmd == LC_FILESET_ENTRY && cmdsize >= 28) {
            if (!rd64(buf, len, cursor + 16, &fileoff) ||
                !rd32(buf, len, cursor + 24, &name_off) ||
                name_off >= cmdsize) {
                return false;
            }
            uint64_t ns = cursor + name_off;
            size_t max = cursor + cmdsize - ns;
            if (fileoff < len && strnlen((const char *)(buf + ns), max) < max &&
                !strcmp((const char *)(buf + ns), name)) {
                *out_fileoff = fileoff;
                return true;
            }
        }
        cursor += cmdsize;
    }
    return false;
}

bool apple_modern_kc_ignition_compat(uint8_t *bootkc, size_t len, Error **errp)
{
    uint64_t kext, texec_off, texec_size, data_off, data_size;
    uint64_t cstr_off, cstr_size, str_off = 0, handler_raw, handler;
    uint32_t first = 0; /* -O2 -Werror=maybe-uninitialized: only read when
                         * rd32() above succeeded, which the compiler cannot see. */
    const char *needle = "ignition_blob";
    size_t nlen = strlen(needle);

    if (!find_fileset_entry(bootkc, len, "com.apple.security.AppleImage4",
                            &kext)) {
        error_setg(errp, "img4-ignition-compat: AppleImage4 kext not found");
        return false;
    }
    if (!find_segment(bootkc, len, kext, "__TEXT_EXEC", NULL,
                      &texec_off, &texec_size) ||
        !find_segment(bootkc, len, kext, "__DATA", "__data",
                      &data_off, &data_size) ||
        !find_segment(bootkc, len, kext, "__TEXT", "__cstring",
                      &cstr_off, &cstr_size)) {
        error_setg(errp, "img4-ignition-compat: AppleImage4 sections not found");
        return false;
    }
    if (cstr_off > len || cstr_size > len - cstr_off ||
        data_off > len || data_size > len - data_off ||
        texec_off > len || texec_size > len - texec_off) {
        error_setg(errp, "img4-ignition-compat: section outside image");
        return false;
    }

    for (uint64_t i = 0; i + nlen + 1 <= cstr_size; i++) {
        if (!memcmp(bootkc + cstr_off + i, needle, nlen + 1)) {
            str_off = cstr_off + i;
            break;
        }
    }
    if (!str_off) {
        error_setg(errp, "img4-ignition-compat: ignition_blob string not found");
        return false;
    }

    handler = 0;
    for (uint64_t i = 0; i + 8 <= data_size; i += 8) {
        uint64_t p = ldq_le_p(bootkc + data_off + i);

        if ((p & KC_FIXUP_TARGET_MASK) != str_off) {
            continue;
        }
        /* This pointer is sysctl_oid.oid_name; read its oid_handler. */
        uint64_t name_field = data_off + i;
        if (name_field < OID_NAME_OFFSET) {
            continue;
        }
        uint64_t handler_field = name_field - OID_NAME_OFFSET + OID_HANDLER_OFFSET;
        if (!rd64(bootkc, len, handler_field, &handler_raw)) {
            continue;
        }
        handler = handler_raw & KC_FIXUP_TARGET_MASK;
        break;
    }
    if (!handler) {
        error_setg(errp, "img4-ignition-compat: ignition_blob sysctl not found");
        return false;
    }
    if (handler < texec_off || handler > texec_off + texec_size - 12) {
        error_setg(errp, "img4-ignition-compat: handler outside __TEXT_EXEC");
        return false;
    }
    if (!rd32(bootkc, len, handler, &first) ||
        (first != INSN_PACIBSP && first != INSN_BTI_C)) {
        error_setg(errp, "img4-ignition-compat: unexpected handler prologue "
                   "0x%08x", first);
        return false;
    }

    /* pacibsp ; movz x0, #0 ; retab  -> return 0 with no blob. */
    stl_le_p(bootkc + handler, INSN_PACIBSP);
    stl_le_p(bootkc + handler + 4, INSN_MOVZ_X0_0);
    stl_le_p(bootkc + handler + 8, INSN_RETAB);
    return true;
}

/* ------------------------------------------------------------------------- *
 * md ram-disk width compatibility (opt-in; see modern-kc-patch.h for the
 * published-source root cause, the exact file:line list and what it removes).
 *
 * Every mask/value below is the AArch64 encoding of an instruction form that
 * Apple's published memdev.c expressions compile to; none of them was taken
 * from the shipped binary. The register fields are masked out and then tied
 * together by the dataflow the C source itself states, so the anchor cannot
 * match an unrelated 32-bit shift.
 * ------------------------------------------------------------------------- */

/* LDR Wt, [Xn, #imm]  (unsigned offset, 32-bit) */
#define LDR_W_UIMM_MASK     0xFFC00000u
#define LDR_W_UIMM_VAL      0xB9400000u
/* LSL Wd, Wn, #12  == UBFM Wd, Wn, #20, #19 */
#define LSL_W_12_MASK       0xFFFFFC00u
#define LSL_W_12_VAL        0x53144C00u
/* LSL Xd, Xn, #12  == UBFM Xd, Xn, #52, #51 */
#define LSL_X_12_VAL        0xD374CC00u
/* CMP Xn, Xm  == SUBS XZR, Xn, Xm (shifted register, LSL #0) */
#define CMP_X_REG_MASK      0xFFE0FC1Fu
#define CMP_X_REG_VAL       0xEB00001Fu
/* B.HS (unsigned higher or same), the `blkoff >= end` branch */
#define BCOND_MASK          0xFF00001Fu
#define BCOND_HS_VAL        0x54000002u
/* ADD Wd, Wn, Wm, LSL #12 */
#define ADD_W_LSL12_MASK    0xFFE0FC00u
#define ADD_W_LSL12_VAL     0x0B003000u
/* SUB Wd, Wn, #1 */
#define SUB_W_IMM1_MASK     0xFFFFFC00u
#define SUB_W_IMM1_VAL      0x51000400u
/* UDIV Wd, Wn, Wm */
#define UDIV_W_MASK         0xFFE0FC00u
#define UDIV_W_VAL          0x1AC00800u
/* The sf bit: setting it turns ADD/SUB-immediate/UDIV from 32 to 64 bit. */
#define INSN_SF_BIT         0x80000000u

/* struct mdev (xnu bsd/dev/memdev.c:160): mdSize at +8, mdSecsize at +16. */
#define MDEV_MDSIZE_OFFSET      8u
#define MDEV_MDSECSIZE_OFFSET   16u

#define INSN_RD(x)  ((x) & 0x1Fu)
#define INSN_RN(x)  (((x) >> 5) & 0x1Fu)
#define INSN_RM(x)  (((x) >> 16) & 0x1Fu)

static bool insn_ldr_w(uint32_t insn, uint32_t offset, uint32_t *rt,
                       uint32_t *rn)
{
    if ((insn & LDR_W_UIMM_MASK) != LDR_W_UIMM_VAL) {
        return false;
    }
    if ((((insn >> 10) & 0xFFFu) * 4u) != offset) {
        return false;
    }
    *rt = INSN_RD(insn);
    *rn = INSN_RN(insn);
    return true;
}

/*
 * mdevstrategy, memdev.c:270..292:
 *   ldr   Wa, [Xb, #8]          ; mdev[devid].mdSize
 *   lsl   Wa, Wa, #12           ; 32-bit: wraps for >= 4 GiB
 *   cmp   Xc, Xa                ; blkoff >= end
 *   b.hs  ...
 * The compiler keeps the shifted value, so the later past-end test and the
 * trim reuse the same register and are fixed by widening this one shift.
 */
static bool match_strategy(const uint8_t *text, uint64_t off, uint64_t left,
                           uint32_t *reg)
{
    uint32_t w[4], rt, rn;

    if (left < 16) {
        return false;
    }
    for (unsigned i = 0; i < 4; i++) {
        w[i] = ldl_le_p(text + off + i * 4);
    }
    if (!insn_ldr_w(w[0], MDEV_MDSIZE_OFFSET, &rt, &rn)) {
        return false;
    }
    if ((w[1] & LSL_W_12_MASK) != LSL_W_12_VAL ||
        INSN_RD(w[1]) != rt || INSN_RN(w[1]) != rt) {
        return false;
    }
    if ((w[2] & CMP_X_REG_MASK) != CMP_X_REG_VAL || INSN_RM(w[2]) != rt) {
        return false;
    }
    if ((w[3] & BCOND_MASK) != BCOND_HS_VAL) {
        return false;
    }
    *reg = rt;
    return true;
}

/*
 * mdevioctl DKIOCGETBLOCKCOUNT, memdev.c:433..437:
 *   ldr   Wa, [Xb, #8]          ; mdSize
 *   ldr   Wc, [Xb, #16]         ; mdSecsize
 *   add   Wd, Wc, Wa, lsl #12   ; 32-bit: wraps for >= 4 GiB
 *   sub   Wd, Wd, #1
 *   udiv  We, Wd, Wc
 */
static bool match_blockcount(const uint8_t *text, uint64_t off, uint64_t left)
{
    uint32_t w[5], size_rt, size_rn, secs_rt, secs_rn, acc;

    if (left < 20) {
        return false;
    }
    for (unsigned i = 0; i < 5; i++) {
        w[i] = ldl_le_p(text + off + i * 4);
    }
    if (!insn_ldr_w(w[0], MDEV_MDSIZE_OFFSET, &size_rt, &size_rn) ||
        !insn_ldr_w(w[1], MDEV_MDSECSIZE_OFFSET, &secs_rt, &secs_rn) ||
        secs_rn != size_rn) {
        return false;
    }
    if ((w[2] & ADD_W_LSL12_MASK) != ADD_W_LSL12_VAL ||
        INSN_RM(w[2]) != size_rt || INSN_RN(w[2]) != secs_rt) {
        return false;
    }
    acc = INSN_RD(w[2]);
    if ((w[3] & SUB_W_IMM1_MASK) != SUB_W_IMM1_VAL ||
        INSN_RD(w[3]) != acc || INSN_RN(w[3]) != acc) {
        return false;
    }
    if ((w[4] & UDIV_W_MASK) != UDIV_W_VAL ||
        INSN_RN(w[4]) != acc || INSN_RM(w[4]) != secs_rt) {
        return false;
    }
    return true;
}

bool apple_modern_kc_md0_width_compat(uint8_t *bootkc, size_t len,
                                      AppleModernMd0WidthPatch *out,
                                      Error **errp)
{
    uint64_t kernel, texec_off, texec_size;
    uint64_t strategy = 0, blockcount = 0;
    unsigned strategy_hits = 0, blockcount_hits = 0;
    uint32_t strategy_reg = 0;

    if (!bootkc) {
        error_setg(errp, "md0-width-compat: no kernel cache");
        return false;
    }
    if (!find_fileset_entry(bootkc, len, "com.apple.kernel", &kernel)) {
        error_setg(errp, "md0-width-compat: com.apple.kernel fileset entry "
                   "not found");
        return false;
    }
    if (!find_segment(bootkc, len, kernel, "__TEXT_EXEC", NULL,
                      &texec_off, &texec_size)) {
        error_setg(errp, "md0-width-compat: kernel __TEXT_EXEC not found");
        return false;
    }
    if (texec_off > len || texec_size > len - texec_off ||
        (texec_off & 3) != 0 || texec_size < 20) {
        error_setg(errp, "md0-width-compat: kernel __TEXT_EXEC outside image "
                   "or unaligned");
        return false;
    }

    /*
     * Count every match first. Nothing is written unless both anchors matched
     * exactly once, so an ambiguous or absent anchor leaves the image intact.
     */
    for (uint64_t off = 0; off + 4 <= texec_size; off += 4) {
        uint32_t reg;

        if (match_strategy(bootkc + texec_off, off, texec_size - off, &reg)) {
            strategy_hits++;
            strategy = texec_off + off;
            strategy_reg = reg;
        }
        if (match_blockcount(bootkc + texec_off, off, texec_size - off)) {
            blockcount_hits++;
            blockcount = texec_off + off;
        }
    }

    if (strategy_hits != 1) {
        error_setg(errp, "md0-width-compat: mdevstrategy size anchor matched "
                   "%u times in the kernel __TEXT_EXEC, expected exactly 1; "
                   "refusing to patch", strategy_hits);
        return false;
    }
    if (blockcount_hits != 1) {
        error_setg(errp, "md0-width-compat: DKIOCGETBLOCKCOUNT size anchor "
                   "matched %u times in the kernel __TEXT_EXEC, expected "
                   "exactly 1; refusing to patch", blockcount_hits);
        return false;
    }
    /*
     * No overlap check is needed, and one would be unreachable code: the two
     * anchors cannot overlap. At every relative displacement within either
     * anchor's span, some word would have to match two mutually exclusive
     * instruction forms at once - LSL against LDR, LDR against ADD, CMP
     * against SUB, B.cond against UDIV - so the matchers can never both
     * succeed at positions less than one anchor apart. Each anchor is also
     * wholly inside __TEXT_EXEC, because its matcher required 16 or 20 bytes
     * of remaining segment, which is what bounds the four writes below.
     */
    if (out) {
        memset(out, 0, sizeof(*out));
        out->strategy_anchor = strategy;
        out->blockcount_anchor = blockcount;
        out->strategy_before = ldl_le_p(bootkc + strategy + 4);
        for (unsigned i = 0; i < 3; i++) {
            out->blockcount_before[i] =
                ldl_le_p(bootkc + blockcount + 8 + i * 4);
        }
    }

    /* mdevstrategy: LSL Wa, Wa, #12  ->  LSL Xa, Xa, #12. */
    stl_le_p(bootkc + strategy + 4,
             LSL_X_12_VAL | (strategy_reg << 5) | strategy_reg);
    /* DKIOCGETBLOCKCOUNT: widen ADD / SUB #1 / UDIV from 32 to 64 bit. */
    for (unsigned i = 0; i < 3; i++) {
        uint64_t at = blockcount + 8 + i * 4;

        stl_le_p(bootkc + at, ldl_le_p(bootkc + at) | INSN_SF_BIT);
    }

    if (out) {
        out->strategy_after = ldl_le_p(bootkc + strategy + 4);
        for (unsigned i = 0; i < 3; i++) {
            out->blockcount_after[i] =
                ldl_le_p(bootkc + blockcount + 8 + i * 4);
        }
    }
    return true;
}

/* ------------------------------------------------------------------------- *
 * Root-remount read/write compatibility (opt-in; see modern-kc-patch.h for
 * the published-source root cause in bsd/vfs/vfs_syscalls.c:1066-1092).
 * ------------------------------------------------------------------------- */

/* LDRB Wt, [Xn, #84]  (struct vnode.v_flag at +84, bsd/sys/vnode_internal.h) */
#define LDRB_W_84_MASK      0xFFFFFC00u
#define LDRB_W_84_VAL       0x39415000u
/* TBZ Wt, #0, label   (vp->v_flag & VROOT) */
#define TBZ_W_BIT0_MASK     0xFFF80000u
#define TBZ_W_BIT0_VAL      0x36000000u
/* LDRB Wt, [Xn, #113] (byte +1 of struct mount.mnt_flag at +112) */
#define LDRB_W_113_MASK     0xFFFFFC00u
#define LDRB_W_113_VAL      0x3941C400u
/* TBNZ Wt, #6, label  (vp->v_mount->mnt_flag & MNT_ROOTFS) */
#define TBNZ_W_BIT6_MASK    0xFFF80000u
#define TBNZ_W_BIT6_VAL     0x37300000u
/* ORR Wd, Wn, #0x10000 (flags |= MNT_UPDATE) */
#define ORR_W_10000_MASK    0xFFFFFC00u
#define ORR_W_10000_VAL     0x32100000u
/* TBNZ Wt, #0, label  (flags & MNT_RDONLY) */
#define TBNZ_W_BIT0_MASK    0xFFF80000u
#define TBNZ_W_BIT0_VAL     0x37000000u
/* MOVZ Wd, #1         (error = EPERM) */
#define MOVZ_W_1_MASK       0xFFFFFFE0u
#define MOVZ_W_1_VAL        0x52800020u
/* B label             (unconditional branch) */
#define B_UNCOND_VAL        0x14000000u

static bool match_mac_mount_root_check(const uint8_t *text, uint64_t off,
                                       uint64_t total_size,
                                       uint64_t *update_off_out)
{
    uint32_t w0, w1, w6, w7, t0, t1, t2;
    int32_t imm14;
    uint64_t target_off;

    if (off + 32 > total_size) {
        return false;
    }
    w0 = ldl_le_p(text + off);
    w1 = ldl_le_p(text + off + 4);
    w6 = ldl_le_p(text + off + 24);
    w7 = ldl_le_p(text + off + 28);

    if ((w0 & LDRB_W_84_MASK) != LDRB_W_84_VAL ||
        (w1 & TBZ_W_BIT0_MASK) != TBZ_W_BIT0_VAL ||
        INSN_RD(w1) != INSN_RD(w0)) {
        return false;
    }
    if ((w6 & LDRB_W_113_MASK) != LDRB_W_113_VAL ||
        (w7 & TBNZ_W_BIT6_MASK) != TBNZ_W_BIT6_VAL ||
        INSN_RD(w7) != INSN_RD(w6)) {
        return false;
    }

    imm14 = ((int32_t)(w7 << 13)) >> 18;
    if (imm14 <= 0) {
        return false;
    }
    target_off = off + 28 + (uint64_t)imm14 * 4u;
    if (target_off + 12 > total_size) {
        return false;
    }

    t0 = ldl_le_p(text + target_off);
    t1 = ldl_le_p(text + target_off + 4);
    t2 = ldl_le_p(text + target_off + 8);

    if ((t0 & ORR_W_10000_MASK) != ORR_W_10000_VAL ||
        (t1 & TBNZ_W_BIT0_MASK) != TBNZ_W_BIT0_VAL ||
        INSN_RD(t1) != INSN_RN(t0) ||
        (t2 & MOVZ_W_1_MASK) != MOVZ_W_1_VAL) {
        return false;
    }

    *update_off_out = target_off;
    return true;
}

/*
 * vfs_rootmountalloc_internal (bsd/vfs/vfs_subr.c:1145-1150):
 *   movz  Wa, #0xb7fe           ; low 16 of MNT_VISFLAGMASK & ~(MNT_RDONLY|MNT_ROOTFS)
 *   movk  Wa, #0xdff0, lsl #16  ; high 16 of 0xdff0b7fe
 *   and   Wb, Wc, Wa
 *   movz  Wd, #0x4001           ; MNT_RDONLY | MNT_ROOTFS
 *   orr   We, Wb, Wd
 *   str   We, [Xmp, #112]       ; mp->mnt_flag
 */
static bool match_rootmountalloc(const uint8_t *text, uint64_t off,
                                 uint64_t left)
{
    uint32_t w[6], reg_a, reg_b, reg_d, reg_e;

    if (left < 24) {
        return false;
    }
    for (unsigned i = 0; i < 6; i++) {
        w[i] = ldl_le_p(text + off + i * 4);
    }
    if ((w[0] & 0xFFFFFFE0u) != 0x5296FFC0u ||
        (w[1] & 0xFFFFFFE0u) != 0x72BBFE00u ||
        INSN_RD(w[1]) != INSN_RD(w[0])) {
        return false;
    }
    reg_a = INSN_RD(w[0]);
    if ((w[2] & 0xFFE0FC00u) != 0x0A000000u ||
        (INSN_RM(w[2]) != reg_a && INSN_RN(w[2]) != reg_a)) {
        return false;
    }
    reg_b = INSN_RD(w[2]);
    if ((w[3] & 0xFFFFFFE0u) != 0x52880020u) {
        return false;
    }
    reg_d = INSN_RD(w[3]);
    if ((w[4] & 0xFFE0FC00u) != 0x2A000000u) {
        return false;
    }
    if (!((INSN_RN(w[4]) == reg_b && INSN_RM(w[4]) == reg_d) ||
          (INSN_RN(w[4]) == reg_d && INSN_RM(w[4]) == reg_b))) {
        return false;
    }
    reg_e = INSN_RD(w[4]);
    if ((w[5] & 0xFFFFFC00u) != 0xB9007000u || INSN_RD(w[5]) != reg_e) {
        return false;
    }
    return true;
}

bool apple_modern_kc_root_rw_compat(uint8_t *bootkc, size_t len,
                                    AppleModernRootRwPatch *out,
                                    Error **errp)
{
    uint64_t kernel, texec_off, texec_size;
    uint64_t check_anchor = 0, update_anchor = 0, rma_anchor = 0;
    unsigned hits = 0, rma_hits = 0;
    uint32_t before, after, rma_before, rma_after;
    int32_t disp;

    if (!bootkc) {
        error_setg(errp, "root-rw-compat: no kernel cache");
        return false;
    }
    if (!find_fileset_entry(bootkc, len, "com.apple.kernel", &kernel)) {
        error_setg(errp, "root-rw-compat: com.apple.kernel fileset entry "
                   "not found");
        return false;
    }
    if (!find_segment(bootkc, len, kernel, "__TEXT_EXEC", NULL,
                      &texec_off, &texec_size)) {
        error_setg(errp, "root-rw-compat: kernel __TEXT_EXEC not found");
        return false;
    }
    if (texec_off > len || texec_size > len - texec_off ||
        (texec_off & 3) != 0 || texec_size < 32) {
        error_setg(errp, "root-rw-compat: kernel __TEXT_EXEC outside image "
                   "or unaligned");
        return false;
    }

    for (uint64_t off = 0; off + 24 <= texec_size; off += 4) {
        uint64_t uoff = 0;

        if (off + 32 <= texec_size &&
            match_mac_mount_root_check(bootkc + texec_off, off, texec_size,
                                       &uoff)) {
            hits++;
            check_anchor = texec_off + off;
            update_anchor = texec_off + uoff;
        }
        if (match_rootmountalloc(bootkc + texec_off, off, texec_size - off)) {
            rma_hits++;
            rma_anchor = texec_off + off;
        }
    }
    if (rma_hits != 1) {
        error_setg(errp, "root-rw-compat: vfs_rootmountalloc_internal anchor "
                   "matched %u times in the kernel __TEXT_EXEC, expected "
                   "exactly 1; refusing to patch", rma_hits);
        return false;
    }
    if (hits != 1) {
        error_setg(errp, "root-rw-compat: __mac_mount root-update anchor "
                   "matched %u times in the kernel __TEXT_EXEC, expected "
                   "exactly 1; refusing to patch", hits);
        return false;
    }

    /*
     * vfs_rootmountalloc_internal (bsd/vfs/vfs_subr.c:1147):
     *   MOVZ Wd, #0x4001 (MNT_RDONLY | MNT_ROOTFS) -> MOVZ Wd, #0
     * so apfs_vfsop_mountroot / apfs_mount_livefs mounts the root volume
     * read/write during vfs_mountroot(), and bsd_init() (bsd/kern/bsd_init.c:918)
     * then sets mountlist.tqh_first->mnt_flag |= MNT_ROOTFS immediately after
     * vfs_mountroot() returns 0.
     */
    rma_before = ldl_le_p(bootkc + rma_anchor + 12);
    rma_after = 0x52800000u | INSN_RD(rma_before);
    stl_le_p(bootkc + rma_anchor + 12, rma_after);

    before = ldl_le_p(bootkc + update_anchor + 4);
    disp = ((int32_t)(before << 13)) >> 18;
    after = B_UNCOND_VAL | ((uint32_t)disp & 0x03FFFFFFu);
    stl_le_p(bootkc + update_anchor + 4, after);

    if (out) {
        out->rootmountalloc_anchor = rma_anchor;
        out->rootmountalloc_before = rma_before;
        out->rootmountalloc_after = rma_after;
        out->check_anchor = check_anchor;
        out->update_anchor = update_anchor;
        out->insn_before = before;
        out->insn_after = after;
    }
    return true;
}

#define INSN_RET            0xd65f03c0u
#define TXM_SC_FN_VA        UINT64_C(0xfffffff017033d00)
#define TXM_SC_GLOBAL_VA    UINT64_C(0xfffffff017088db0)
/* ADRP Xd, 0xfffffff017088000 from PC page 0xfffffff017033000 (+0x55 pages) */
#define ADRP_TXM_SC_MASK    0xffffffe0u
#define ADRP_TXM_SC_VAL     0xb00002a0u

static bool find_segment_and_section_va(const uint8_t *buf, size_t len, uint64_t image_base,
                                        const char *seg, const char *sect,
                                        uint64_t *out_va, uint64_t *out_vmsize,
                                        uint64_t *out_off, uint64_t *out_size)
{
    uint32_t magic, ncmds;
    uint64_t cursor;
    size_t seglen = strlen(seg);

    if (!rd32(buf, len, image_base, &magic) || magic != MH_MAGIC_64 ||
        !rd32(buf, len, image_base + 16, &ncmds) || ncmds > 4096) {
        return false;
    }
    cursor = image_base + 32;
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd, cmdsize;

        if (!rd32(buf, len, cursor, &cmd) ||
            !rd32(buf, len, cursor + 4, &cmdsize) ||
            cmdsize < 8 || cmdsize > len - cursor) {
            return false;
        }
        if (cmd == LC_SEGMENT_64 && cmdsize >= SEG_CMD_MIN && seglen < 16 &&
            !memcmp(buf + cursor + 8, seg, seglen) &&
            buf[cursor + 8 + seglen] == '\0') {
            uint64_t fileoff, filesize, va, vmsize;
            uint32_t nsects;

            if (!rd64(buf, len, cursor + 24, &va) ||
                !rd64(buf, len, cursor + 32, &vmsize) ||
                !rd64(buf, len, cursor + 40, &fileoff) ||
                !rd64(buf, len, cursor + 48, &filesize) ||
                !rd32(buf, len, cursor + 64, &nsects)) {
                return false;
            }
            if (!sect) {
                *out_va = va;
                *out_vmsize = vmsize;
                *out_off = fileoff;
                *out_size = filesize;
                return true;
            }
            if (nsects > (cmdsize - SEG_CMD_MIN) / SECTION_64_SIZE) {
                return false;
            }
            for (uint32_t s = 0; s < nsects; s++) {
                uint64_t so = cursor + SEG_CMD_MIN + (uint64_t)s * SECTION_64_SIZE;
                uint64_t s_vmaddr, s_vmsize;
                uint32_t soff;

                if (so + 48 > len || buf[so + 16 + 15] != '\0' ||
                    strcmp((const char *)(buf + so), sect) != 0) {
                    continue;
                }
                if (!rd64(buf, len, so + 32, &s_vmaddr) ||
                    !rd64(buf, len, so + 40, &s_vmsize) ||
                    !rd32(buf, len, so + 48, &soff)) {
                    return false;
                }
                *out_va = s_vmaddr;
                *out_vmsize = s_vmsize;
                *out_off = soff;
                *out_size = s_vmsize;
                return true;
            }
            return false;
        }
        cursor += cmdsize;
    }
    return false;
}

static bool find_segment_va(const uint8_t *buf, size_t len, uint64_t image_base,
                            const char *seg, uint64_t *out_va,
                            uint64_t *out_vmsize, uint64_t *out_off,
                            uint64_t *out_size)
{
    return find_segment_and_section_va(buf, len, image_base, seg, NULL,
                                       out_va, out_vmsize, out_off, out_size);
}

bool apple_modern_txm_sc_compat(uint8_t *txm, size_t len,
                                AppleModernTxmScPatch *out,
                                Error **errp)
{
    uint64_t texec_va = 0, texec_vmsize = 0, texec_off = 0, texec_size = 0;
    uint64_t data_va = 0, data_vmsize = 0, data_off = 0, data_size = 0;
    uint64_t fn_off;
    uint32_t w0, w1, w2;

    if (!txm) {
        error_setg(errp, "txm-sc-compat: no TXM image");
        return false;
    }
    if (!find_segment_va(txm, len, 0, "__TEXT_EXEC", &texec_va, &texec_vmsize,
                         &texec_off, &texec_size) ||
        !find_segment_va(txm, len, 0, "__DATA", &data_va, &data_vmsize,
                         &data_off, &data_size)) {
        error_setg(errp, "txm-sc-compat: TXM __TEXT_EXEC or __DATA not found");
        return false;
    }
    if (texec_off > len || texec_size > len - texec_off ||
        (texec_off & 3) != 0 || texec_size < 16) {
        error_setg(errp, "txm-sc-compat: TXM __TEXT_EXEC outside image");
        return false;
    }
    if (TXM_SC_FN_VA < texec_va ||
        TXM_SC_FN_VA - texec_va > texec_size - 12) {
        error_setg(errp, "txm-sc-compat: target VA 0x%" PRIx64 " outside "
                   "TXM __TEXT_EXEC", TXM_SC_FN_VA);
        return false;
    }
    if (TXM_SC_GLOBAL_VA < data_va ||
        TXM_SC_GLOBAL_VA - data_va > data_vmsize - 4) {
        error_setg(errp, "txm-sc-compat: global VA 0x%" PRIx64 " outside "
                   "TXM __DATA", TXM_SC_GLOBAL_VA);
        return false;
    }

    fn_off = texec_off + (TXM_SC_FN_VA - texec_va);
    w0 = ldl_le_p(txm + fn_off);
    w1 = ldl_le_p(txm + fn_off + 4);
    w2 = ldl_le_p(txm + fn_off + 8);

    if ((w0 != INSN_BTI_C && w0 != INSN_PACIBSP) ||
        ((w1 & ADRP_TXM_SC_MASK) != ADRP_TXM_SC_VAL &&
         (w2 & ADRP_TXM_SC_MASK) != ADRP_TXM_SC_VAL)) {
        error_setg(errp, "txm-sc-compat: unexpected instructions at 0x%" PRIx64
                   " (file +0x%" PRIx64 "): 0x%08x 0x%08x 0x%08x",
                   TXM_SC_FN_VA, fn_off, w0, w1, w2);
        return false;
    }

    stl_le_p(txm + fn_off + 4, MOVZ_W_1_VAL);
    stl_le_p(txm + fn_off + 8, INSN_RET);

    if (out) {
        out->anchor = fn_off;
        out->prologue = w0;
        out->insn_before[0] = w1;
        out->insn_before[1] = w2;
        out->insn_after[0] = MOVZ_W_1_VAL;
        out->insn_after[1] = INSN_RET;
    }
    return true;
}

bool apple_modern_kc_iouc_sandbox_compat(uint8_t *bootkc, size_t len,
                                         AppleModernIoucPatch *out,
                                         Error **errp)
{
    uint64_t kernel = 0;
    uint64_t texec_va = 0, texec_vmsize = 0, texec_off = 0, texec_size = 0;
    uint64_t cstr_va = 0, cstr_vmsize = 0, cstr_off = 0, cstr_size = 0;
    const char *sb_needle = "IOUC %s failed sandbox in process %s\n";
    size_t sb_needle_len = strlen(sb_needle);
    uint64_t sb_str_off = 0;
    uint64_t sb_xref_off = 0;
    unsigned sb_xref_hits = 0;
    uint64_t kio_off = 0;
    uint64_t beq_off = 0, allow_pc = 0;
    uint64_t cbnz_off = 0, deny_pc = 0, deny_fo = 0;
    uint32_t b_allow_insn = 0;
    int64_t disp_bytes = 0, disp_insns = 0;

    const char *macf_needle = "IOUC %s failed MACF in process %s\n";
    size_t macf_needle_len = strlen(macf_needle);
    uint64_t macf_str_off = 0;
    uint64_t macf_xref_off = 0;
    unsigned macf_xref_hits = 0;
    uint64_t macf_cbz_off = 0, macf_allow_pc = 0;
    uint32_t b_macf_allow_insn = 0;
    int64_t disp_macf_bytes = 0, disp_macf_insns = 0;

    if (!bootkc) {
        error_setg(errp, "iouc-sandbox-compat: no kernel cache");
        return false;
    }
    if (!find_fileset_entry(bootkc, len, "com.apple.kernel", &kernel)) {
        error_setg(errp, "iouc-sandbox-compat: com.apple.kernel fileset entry not found");
        return false;
    }
    if (!find_segment_and_section_va(bootkc, len, kernel, "__TEXT_EXEC", NULL,
                                     &texec_va, &texec_vmsize, &texec_off, &texec_size) ||
        !find_segment_and_section_va(bootkc, len, kernel, "__TEXT", "__cstring",
                                     &cstr_va, &cstr_vmsize, &cstr_off, &cstr_size)) {
        error_setg(errp, "iouc-sandbox-compat: kernel __TEXT_EXEC or __cstring not found");
        return false;
    }
    if (texec_off > len || texec_size > len - texec_off ||
        cstr_off > len || cstr_size > len - cstr_off ||
        (texec_off & 3) != 0 || texec_size < 32) {
        error_setg(errp, "iouc-sandbox-compat: segments misaligned or outside image");
        return false;
    }

    /* 1. Sandbox string in __cstring */
    for (uint64_t i = 0; i + sb_needle_len + 1 <= cstr_size; i++) {
        if (!memcmp(bootkc + cstr_off + i, sb_needle, sb_needle_len + 1)) {
            sb_str_off = cstr_off + i;
            break;
        }
    }
    if (!sb_str_off) {
        error_setg(errp, "iouc-sandbox-compat: sandbox failure string not found");
        return false;
    }
    uint64_t sb_str_va = cstr_va + (sb_str_off - cstr_off);
    uint64_t sb_page = sb_str_va & ~0xfffULL;
    uint64_t sb_page_off = sb_str_va & 0xfffULL;

    /* 2. ADRP+ADD xref in __TEXT_EXEC */
    for (uint64_t off = 0; off + 8 <= texec_size; off += 4) {
        uint64_t pc = texec_va + off;
        uint64_t pc_page = pc & ~0xfffULL;
        uint32_t w = ldl_le_p(bootkc + texec_off + off);
        if ((w & 0x9f000000u) == 0x90000000u) {
            uint32_t immlo = (w >> 29) & 3u;
            uint32_t immhi = (w >> 5) & 0x7ffffu;
            int64_t imm = (int64_t)((immhi << 2) | immlo);
            if (imm & 0x100000) {
                imm -= 0x200000;
            }
            if ((uint64_t)((int64_t)pc_page + (imm << 12)) == sb_page) {
                uint32_t nw = ldl_le_p(bootkc + texec_off + off + 4);
                if ((nw & 0xffc00000u) == 0x91000000u) {
                    uint32_t add_imm12 = (nw >> 10) & 0xfffu;
                    if (add_imm12 == sb_page_off) {
                        sb_xref_hits++;
                        sb_xref_off = texec_off + off;
                    }
                }
            }
        }
    }
    if (sb_xref_hits != 1) {
        error_setg(errp, "iouc-sandbox-compat: sandbox xref matched %u times, expected 1", sb_xref_hits);
        return false;
    }

    /* 3. Search backward for MOVZ Wn, #0x2c7 ; MOVK Wn, #0xe000, LSL #16 */
    for (uint64_t back = 4; back <= 160 && sb_xref_off >= texec_off + back; back += 4) {
        uint64_t cand = sb_xref_off - back;
        uint32_t w1 = ldl_le_p(bootkc + cand);
        uint32_t w2 = ldl_le_p(bootkc + cand + 4);
        if ((w1 & 0xffffffe0u) == 0x528058e0u && (w2 & 0xffffffe0u) == 0x72bc0000u) {
            kio_off = cand;
            break;
        }
    }
    if (!kio_off) {
        error_setg(errp, "iouc-sandbox-compat: kIOReturnNotPermitted immediate not found");
        return false;
    }

    /* 4. Find B.EQ */
    for (uint64_t fwd = 8; fwd <= 24 && kio_off + fwd < texec_off + texec_size; fwd += 4) {
        uint64_t cand = kio_off + fwd;
        uint32_t w = ldl_le_p(bootkc + cand);
        if ((w & 0xff00001fu) == 0x54000000u) {
            int32_t imm19 = ((int32_t)(w << 8)) >> 13;
            uint64_t pc = texec_va + (cand - texec_off);
            allow_pc = pc + (int64_t)imm19 * 4;
            beq_off = cand;
            break;
        }
    }
    if (!beq_off) {
        error_setg(errp, "iouc-sandbox-compat: B.EQ allow branch not found");
        return false;
    }

    /* 5. Find CBNZ */
    for (uint64_t fwd = 4; fwd <= 16 && beq_off + fwd < texec_off + texec_size; fwd += 4) {
        uint64_t cand = beq_off + fwd;
        uint32_t w = ldl_le_p(bootkc + cand);
        if ((w & 0xff000000u) == 0x35000000u) {
            int32_t imm19 = ((int32_t)(w << 8)) >> 13;
            uint64_t pc = texec_va + (cand - texec_off);
            deny_pc = pc + (int64_t)imm19 * 4;
            cbnz_off = cand;
            break;
        }
    }
    if (!cbnz_off) {
        error_setg(errp, "iouc-sandbox-compat: CBNZ deny branch not found");
        return false;
    }
    deny_fo = texec_off + (deny_pc - texec_va);
    if (deny_fo >= sb_xref_off || deny_fo < texec_off) {
        error_setg(errp, "iouc-sandbox-compat: <DENY> target out of bounds");
        return false;
    }
    disp_bytes = (int64_t)(allow_pc - deny_pc);
    if ((disp_bytes & 3) != 0) {
        error_setg(errp, "iouc-sandbox-compat: branch displacement unaligned");
        return false;
    }
    disp_insns = disp_bytes / 4;
    b_allow_insn = 0x14000000u | ((uint32_t)disp_insns & 0x03ffffffu);

    /* 6. MACF string in __cstring */
    for (uint64_t i = 0; i + macf_needle_len + 1 <= cstr_size; i++) {
        if (!memcmp(bootkc + cstr_off + i, macf_needle, macf_needle_len + 1)) {
            macf_str_off = cstr_off + i;
            break;
        }
    }
    if (!macf_str_off) {
        error_setg(errp, "iouc-sandbox-compat: MACF failure string not found");
        return false;
    }
    uint64_t macf_str_va = cstr_va + (macf_str_off - cstr_off);
    uint64_t macf_page = macf_str_va & ~0xfffULL;
    uint64_t macf_page_off = macf_str_va & 0xfffULL;

    /* 7. MACF ADRP+ADD xref */
    for (uint64_t off = 0; off + 8 <= texec_size; off += 4) {
        uint64_t pc = texec_va + off;
        uint64_t pc_page = pc & ~0xfffULL;
        uint32_t w = ldl_le_p(bootkc + texec_off + off);
        if ((w & 0x9f000000u) == 0x90000000u) {
            uint32_t immlo = (w >> 29) & 3u;
            uint32_t immhi = (w >> 5) & 0x7ffffu;
            int64_t imm = (int64_t)((immhi << 2) | immlo);
            if (imm & 0x100000) {
                imm -= 0x200000;
            }
            if ((uint64_t)((int64_t)pc_page + (imm << 12)) == macf_page) {
                uint32_t nw = ldl_le_p(bootkc + texec_off + off + 4);
                if ((nw & 0xffc00000u) == 0x91000000u) {
                    uint32_t add_imm12 = (nw >> 10) & 0xfffu;
                    if (add_imm12 == macf_page_off) {
                        macf_xref_hits++;
                        macf_xref_off = texec_off + off;
                    }
                }
            }
        }
    }
    if (macf_xref_hits != 1) {
        error_setg(errp, "iouc-sandbox-compat: MACF xref matched %u times, expected 1", macf_xref_hits);
        return false;
    }

    /* 8. MACF CBZ W0 backward search */
    for (uint64_t back = 4; back <= 120 && macf_xref_off >= texec_off + back; back += 4) {
        uint64_t cand = macf_xref_off - back;
        uint32_t w = ldl_le_p(bootkc + cand);
        if ((w & 0xff00001fu) == 0x34000000u) { /* CBZ W0 */
            int32_t imm19 = ((int32_t)(w << 8)) >> 13;
            uint64_t pc = texec_va + (cand - texec_off);
            macf_allow_pc = pc + (int64_t)imm19 * 4;
            macf_cbz_off = cand;
            break;
        }
    }
    if (!macf_cbz_off) {
        error_setg(errp, "iouc-sandbox-compat: MACF CBZ W0 not found");
        return false;
    }
    disp_macf_bytes = (int64_t)(macf_allow_pc - (texec_va + (macf_cbz_off - texec_off)));
    disp_macf_insns = disp_macf_bytes / 4;
    b_macf_allow_insn = 0x14000000u | ((uint32_t)disp_macf_insns & 0x03ffffffu);

    if (out) {
        out->sandbox_deny_anchor = deny_fo;
        out->sandbox_deny_before = ldl_le_p(bootkc + deny_fo);
        out->sandbox_deny_after = b_allow_insn;
        out->macf_gate_anchor = macf_cbz_off;
        out->macf_gate_before = ldl_le_p(bootkc + macf_cbz_off);
        out->macf_gate_after = b_macf_allow_insn;
    }

    /* Apply writes */
    stl_le_p(bootkc + deny_fo, b_allow_insn);
    stl_le_p(bootkc + macf_cbz_off, b_macf_allow_insn);
    return true;
}

/* ------------------------------------------------------------------------- *
 * HID static-config compatibility (opt-in; see modern-kc-patch.h for the RE
 * root cause, the exact unslid VAs and what this replaces). Rewrites the
 * AppleHIDTransportDeviceFIFO getStaticConfig NULL stub so startGated can hand
 * cacheConfig a Protocol-bearing OSDictionary, clearing "No protocol
 * specified", without a live MTP firmware download.
 * ------------------------------------------------------------------------- */

/*
 * The MTP Config dict OSUnserializeXML builds at run time. Real values from the
 * pinned FTAB personality MTP_SYS[0].Config (re/mtpfw/iokt.json): exactly the
 * keys cacheConfig ("Protocol") and the SCMFIFO protocol configure method
 * (vtable +0x600: Interfaces, MaxReadSize, MaxWriteSize, MemoryFifos) consume.
 * The per-interface Reporters/Channels/reset-sequence sub-arrays are omitted on
 * purpose: configure() stores the Interfaces array by reference and logs its
 * count but never walks it, and the whole dict (~58 KiB of XML) would not fit
 * in a provably-unused code cave. A bare <dict> (no <?xml?>/<plist> wrapper) is
 * what the kernel OSUnserializeXML grammar accepts.
 */
static const char apple_modern_hid_static_config_xml[] =
    "<dict>"
    "<key>Client</key><string>D47</string>"
    "<key>Version</key><string>AppleMTPFirmwarePhone-6100.84.6.1~361</string>"
    "<key>Allocation</key><string>1310720</string>"
    "<key>Protocol</key><string>SCMFIFO</string>"
    "<key>MaxReadSize</key><integer>16384</integer>"
    "<key>MaxWriteSize</key><integer>16384</integer>"
    "<key>MemoryFifos</key><array>"
        "<dict><key>WriteSize</key><integer>0</integer>"
            "<key>ReadSize</key><integer>2097152</integer></dict>"
        "<dict><key>WriteSize</key><integer>0</integer>"
            "<key>ReadSize</key><integer>2097152</integer></dict>"
    "</array>"
    "<key>Interfaces</key><array>"
        "<dict><key>bInterfaceNumber</key><integer>0</integer>"
            "<key>InterfaceName</key><string>comm</string></dict>"
        "<dict><key>bInterfaceNumber</key><integer>1</integer>"
            "<key>InterfaceName</key><string>multi-touch</string>"
            "<key>AsyncRegistration</key><true/><key>PowerMethod</key><integer>2</integer>"
            "<key>NotifyPowerStateChange</key><true/><key>NotifyAllResets</key><false/></dict>"
        "<dict><key>bInterfaceNumber</key><integer>3</integer>"
            "<key>InterfaceName</key><string>nova</string>"
            "<key>AsyncRegistration</key><true/><key>PowerMethod</key><integer>2</integer>"
            "<key>NotifyPowerStateChange</key><true/><key>NotifyAllResets</key><false/>"
            "<key>HIDServiceEnabled</key><true/></dict>"
        "<dict><key>bInterfaceNumber</key><integer>2</integer>"
            "<key>InterfaceName</key><string>mtp</string>"
            "<key>AsyncRegistration</key><true/></dict>"
    "</array>"
    "</dict>";

#define HID_FIFO_FILESET        "com.apple.driver.AppleHIDTransportFIFO"
#define HID_BASE_FILESET        "com.apple.driver.AppleHIDTransport"
#define HID_CACHECONFIG_SLOT    UINT64_C(0x570)
#define HID_GETSTATICCFG_SLOT   UINT64_C(0x6e8)
/* AppleHIDTransport's GOT import thunk for OSUnserializeXML (orientation; its
 * shape and resolved target are verified before use). */
#define HID_OSUNSERIALIZE_THUNK_VA  UINT64_C(0xfffffff008e99c24)

#define INSN_MOVZ_X1_0      0xd2800001u /* movz x1, #0 */
#define INSN_BRAA_X16_X17   0xd71f0a11u /* braa x16, x17 */
/* OSUnserializeXML prologue: bti c ; mov x4,x1 ; mov x1,#0 ; mov x2,#0. */
#define INSN_MOV_X4_X1      0xaa0103e4u
#define INSN_MOVZ_X2_0      0xd2800002u

/* AArch64 B imm26 is scaled by 4: reachable range is +/- 128 MiB. */
#define B_IMM_LIMIT         ((int64_t)1 << 25)
/* ADRP imm is a signed 21-bit page count. */
#define ADRP_IMM_LIMIT      ((int64_t)1 << 20)

bool apple_modern_kc_hid_static_config(uint8_t *bootkc, size_t len,
                                       AppleModernHidStaticConfigPatch *out,
                                       Error **errp)
{
    uint64_t fifo = 0, base = 0;
    uint64_t gtx_va = 0, gtx_vmsize = 0, gtx_off = 0, gtx_size = 0;
    uint64_t ftx_va = 0, ftx_vmsize = 0, ftx_off = 0, ftx_size = 0;
    uint64_t fdc_va = 0, fdc_vmsize = 0, fdc_off = 0, fdc_size = 0;
    uint64_t btx_va = 0, btx_vmsize = 0, btx_off = 0, btx_size = 0;
    uint64_t kc_base, vtable_off = 0, gsc_off = 0;
    unsigned hits = 0;
    uint32_t w0 = 0, w1 = 0, w2 = 0, w3 = 0, stub_before = 0;
    uint32_t p0 = 0, p1 = 0, p2 = 0, p3 = 0;
    uint64_t thunk_va, thunk_off, got_va, got_off, raw = 0, osu_off;
    int64_t adrp_imm;
    uint64_t seg_end, run_start, cave_off, avail, cave_va, xml_off, xml_va, gsc_va;
    size_t xml_len = sizeof(apple_modern_hid_static_config_xml) - 1;
    uint64_t need = 16 + (uint64_t)xml_len + 1;
    int64_t adrp_pages, bdelta, binsns, sdelta, sinsns;
    uint32_t adrp, add, movz, b_thunk, stub_b;

    if (!bootkc) {
        error_setg(errp, "hid-static-config: no kernel cache");
        return false;
    }
    if (!find_fileset_entry(bootkc, len, HID_FIFO_FILESET, &fifo)) {
        error_setg(errp, "hid-static-config: " HID_FIFO_FILESET
                   " fileset entry not found");
        return false;
    }
    if (!find_fileset_entry(bootkc, len, HID_BASE_FILESET, &base)) {
        error_setg(errp, "hid-static-config: " HID_BASE_FILESET
                   " fileset entry not found");
        return false;
    }
    if (!find_segment_va(bootkc, len, 0, "__TEXT_EXEC",
                         &gtx_va, &gtx_vmsize, &gtx_off, &gtx_size) ||
        !find_segment_va(bootkc, len, fifo, "__TEXT_EXEC",
                         &ftx_va, &ftx_vmsize, &ftx_off, &ftx_size) ||
        !find_segment_va(bootkc, len, fifo, "__DATA_CONST",
                         &fdc_va, &fdc_vmsize, &fdc_off, &fdc_size) ||
        !find_segment_va(bootkc, len, base, "__TEXT_EXEC",
                         &btx_va, &btx_vmsize, &btx_off, &btx_size)) {
        error_setg(errp, "hid-static-config: required HID transport segments "
                   "not found");
        return false;
    }
    if (gtx_off > len || gtx_size > len - gtx_off ||
        ftx_off > len || ftx_size > len - ftx_off ||
        fdc_off > len || fdc_size > len - fdc_off ||
        btx_off > len || btx_size > len - btx_off ||
        ftx_size < 12 || btx_size < 4 || fdc_size < HID_GETSTATICCFG_SLOT + 8) {
        error_setg(errp, "hid-static-config: HID transport segment outside "
                   "image");
        return false;
    }
    /*
     * Every segment in this MH_FILESET cache maps at file offset == vmaddr -
     * kc_base, so a dyld-chained fixup's 30-bit in-cache target is also a file
     * offset. Require that invariant across all four segments before trusting
     * it; otherwise the fixup decode below would be wrong.
     */
    kc_base = gtx_va - gtx_off;
    if (ftx_va - ftx_off != kc_base || fdc_va - fdc_off != kc_base ||
        btx_va - btx_off != kc_base) {
        error_setg(errp, "hid-static-config: inconsistent cache base; refusing "
                   "to decode chained fixups");
        return false;
    }

    /*
     * The FIFO device vtable is the UNIQUE pointer table in the FIFO kext's
     * __DATA_CONST whose getStaticConfig slot (+0x6e8) targets a
     * "bti c; movz x0,#0; ret" NULL stub inside the FIFO __TEXT_EXEC and whose
     * cacheConfig slot (+0x570) targets a function prologue inside the base
     * AppleHIDTransport __TEXT_EXEC (cacheConfig is inherited from the base
     * class). Count every match; nothing is written unless exactly one table
     * matches, so an ambiguous or absent anchor leaves the image intact.
     */
    for (uint64_t o = fdc_off;
         o + HID_GETSTATICCFG_SLOT + 8 <= fdc_off + fdc_size; o += 8) {
        uint64_t graw = 0, craw = 0, gco, cco;
        uint32_t g0 = 0, g1 = 0, g2 = 0, c0 = 0;

        if (!rd64(bootkc, len, o + HID_GETSTATICCFG_SLOT, &graw)) {
            continue;
        }
        gco = graw & KC_FIXUP_TARGET_MASK;
        if (gco < ftx_off || gco > ftx_off + ftx_size - 12) {
            continue;
        }
        if (!rd32(bootkc, len, gco, &g0) || !rd32(bootkc, len, gco + 4, &g1) ||
            !rd32(bootkc, len, gco + 8, &g2) ||
            g0 != INSN_BTI_C || g1 != INSN_MOVZ_X0_0 || g2 != INSN_RET) {
            continue;
        }
        if (!rd64(bootkc, len, o + HID_CACHECONFIG_SLOT, &craw)) {
            continue;
        }
        cco = craw & KC_FIXUP_TARGET_MASK;
        if (cco < btx_off || cco > btx_off + btx_size - 4) {
            continue;
        }
        if (!rd32(bootkc, len, cco, &c0) ||
            (c0 != INSN_BTI_C && c0 != INSN_PACIBSP)) {
            continue;
        }
        hits++;
        vtable_off = o;
        gsc_off = gco;
    }
    if (hits != 1) {
        error_setg(errp, "hid-static-config: FIFO getStaticConfig vtable anchor "
                   "matched %u times in " HID_FIFO_FILESET " __DATA_CONST, "
                   "expected exactly 1; refusing to patch", hits);
        return false;
    }
    gsc_va = kc_base + gsc_off;

    /*
     * Verify AppleHIDTransport's OSUnserializeXML import thunk: adrp x17,#page ;
     * add x17,x17,#imm ; ldr x16,[x17] ; braa x16,x17. Then follow the GOT entry
     * it loads and confirm the target is really OSUnserializeXML by its
     * prologue, so the tail branch below provably reaches it.
     */
    thunk_va = HID_OSUNSERIALIZE_THUNK_VA;
    if (thunk_va < kc_base) {
        error_setg(errp, "hid-static-config: OSUnserializeXML thunk VA below "
                   "cache base");
        return false;
    }
    thunk_off = thunk_va - kc_base;
    if (thunk_off < gtx_off || thunk_off > gtx_off + gtx_size - 16) {
        error_setg(errp, "hid-static-config: OSUnserializeXML thunk VA outside "
                   "cache __TEXT_EXEC");
        return false;
    }
    if (!rd32(bootkc, len, thunk_off, &w0) ||
        !rd32(bootkc, len, thunk_off + 4, &w1) ||
        !rd32(bootkc, len, thunk_off + 8, &w2) ||
        !rd32(bootkc, len, thunk_off + 12, &w3) ||
        (w0 & 0x9f000000u) != 0x90000000u || (w0 & 0x1fu) != 17 ||
        (w1 & 0xffc00000u) != 0x91000000u || (w1 & 0x1fu) != 17 ||
        ((w1 >> 5) & 0x1fu) != 17 ||
        (w2 & 0xffc00000u) != 0xf9400000u || ((w2 >> 5) & 0x1fu) != 17 ||
        (w2 & 0x1fu) != 16 || w3 != INSN_BRAA_X16_X17) {
        error_setg(errp, "hid-static-config: OSUnserializeXML import thunk shape "
                   "unexpected at 0x%" PRIx64 ": 0x%08x 0x%08x 0x%08x 0x%08x",
                   thunk_va, w0, w1, w2, w3);
        return false;
    }
    adrp_imm = (int64_t)((((w0 >> 5) & 0x7ffffu) << 2) | ((w0 >> 29) & 3u));
    if (adrp_imm & 0x100000) {
        adrp_imm -= 0x200000;
    }
    got_va = (thunk_va & ~UINT64_C(0xfff)) + ((uint64_t)adrp_imm << 12) +
             ((w1 >> 10) & 0xfffu);
    if (got_va < kc_base || got_va - kc_base > len - 8) {
        error_setg(errp, "hid-static-config: OSUnserializeXML GOT slot outside "
                   "image");
        return false;
    }
    got_off = got_va - kc_base;
    if (!rd64(bootkc, len, got_off, &raw)) {
        error_setg(errp, "hid-static-config: cannot read OSUnserializeXML GOT "
                   "slot");
        return false;
    }
    osu_off = raw & KC_FIXUP_TARGET_MASK;
    if (osu_off > len - 16 ||
        !rd32(bootkc, len, osu_off, &p0) || !rd32(bootkc, len, osu_off + 4, &p1) ||
        !rd32(bootkc, len, osu_off + 8, &p2) ||
        !rd32(bootkc, len, osu_off + 12, &p3) ||
        p0 != INSN_BTI_C || p1 != INSN_MOV_X4_X1 || p2 != INSN_MOVZ_X1_0 ||
        p3 != INSN_MOVZ_X2_0) {
        error_setg(errp, "hid-static-config: OSUnserializeXML thunk target "
                   "prologue unexpected: 0x%08x 0x%08x 0x%08x 0x%08x",
                   p0, p1, p2, p3);
        return false;
    }

    /*
     * Code cave: the trailing zero padding of the cache __TEXT_EXEC segment.
     * Scan backward from the segment end for the contiguous zero run, align the
     * start, require room for the 16-byte sequence plus the NUL-terminated XML,
     * and prove every byte it will occupy is zero so nothing live is clobbered.
     */
    seg_end = gtx_off + gtx_size;
    run_start = seg_end;
    while (run_start > gtx_off && bootkc[run_start - 1] == 0) {
        run_start--;
    }
    cave_off = (run_start + 3) & ~UINT64_C(3);
    if (cave_off > seg_end) {
        error_setg(errp, "hid-static-config: no trailing __TEXT_EXEC zero "
                   "padding for a code cave");
        return false;
    }
    avail = seg_end - cave_off;
    if (avail < need) {
        error_setg(errp, "hid-static-config: trailing __TEXT_EXEC zero padding "
                   "is %" PRIu64 " bytes, need %" PRIu64, avail, need);
        return false;
    }
    for (uint64_t i = 0; i < need; i++) {
        if (bootkc[cave_off + i] != 0) {
            error_setg(errp, "hid-static-config: candidate code cave at file "
                       "0x%" PRIx64 " is not zero at +%" PRIu64, cave_off, i);
            return false;
        }
    }
    cave_va = kc_base + cave_off;
    xml_off = cave_off + 16;
    xml_va = kc_base + xml_off;

    /* adrp x0, page(xml) ; add x0, x0, #pageoff(xml) ; movz x1,#0 ; b thunk. */
    adrp_pages = ((int64_t)(xml_va & ~UINT64_C(0xfff)) -
                  (int64_t)(cave_va & ~UINT64_C(0xfff))) >> 12;
    if (adrp_pages < -ADRP_IMM_LIMIT || adrp_pages >= ADRP_IMM_LIMIT) {
        error_setg(errp, "hid-static-config: XML out of ADRP range of the cave");
        return false;
    }
    adrp = 0x90000000u | ((uint32_t)(adrp_pages & 3) << 29) |
           ((uint32_t)((adrp_pages >> 2) & 0x7ffff) << 5);
    add = 0x91000000u | ((uint32_t)(xml_va & 0xfff) << 10);
    movz = INSN_MOVZ_X1_0;
    bdelta = (int64_t)thunk_va - (int64_t)(cave_va + 12);
    if (bdelta & 3) {
        error_setg(errp, "hid-static-config: cave->thunk branch unaligned");
        return false;
    }
    binsns = bdelta >> 2;
    if (binsns < -B_IMM_LIMIT || binsns >= B_IMM_LIMIT) {
        error_setg(errp, "hid-static-config: OSUnserializeXML thunk out of "
                   "branch range of the cave");
        return false;
    }
    b_thunk = 0x14000000u | ((uint32_t)binsns & 0x03ffffffu);

    /* The stub's second word (b <cave>); the first word (bti c) is kept as the
     * indirect-call landing pad. */
    sdelta = (int64_t)cave_va - (int64_t)(gsc_va + 4);
    if (sdelta & 3) {
        error_setg(errp, "hid-static-config: stub->cave branch unaligned");
        return false;
    }
    sinsns = sdelta >> 2;
    if (sinsns < -B_IMM_LIMIT || sinsns >= B_IMM_LIMIT) {
        error_setg(errp, "hid-static-config: code cave out of branch range of "
                   "the stub");
        return false;
    }
    stub_b = 0x14000000u | ((uint32_t)sinsns & 0x03ffffffu);

    /* Verify the exact word being overwritten before touching anything. */
    if (!rd32(bootkc, len, gsc_off + 4, &stub_before) ||
        stub_before != INSN_MOVZ_X0_0) {
        error_setg(errp, "hid-static-config: stub second word is 0x%08x, "
                   "expected movz x0,#0", stub_before);
        return false;
    }

    if (out) {
        memset(out, 0, sizeof(*out));
        out->stub_anchor = gsc_off;
        out->stub_va = gsc_va;
        out->stub_before = stub_before;
        out->stub_after = stub_b;
        out->vtable_va = kc_base + vtable_off;
        out->cave_off = cave_off;
        out->cave_va = cave_va;
        out->xml_off = xml_off;
        out->xml_va = xml_va;
        out->xml_len = (uint32_t)xml_len;
        out->thunk_va = thunk_va;
        out->cave_insns[0] = adrp;
        out->cave_insns[1] = add;
        out->cave_insns[2] = movz;
        out->cave_insns[3] = b_thunk;
    }

    /* Fill the cave first, then arm the stub branch into it. */
    stl_le_p(bootkc + cave_off, adrp);
    stl_le_p(bootkc + cave_off + 4, add);
    stl_le_p(bootkc + cave_off + 8, movz);
    stl_le_p(bootkc + cave_off + 12, b_thunk);
    memcpy(bootkc + xml_off, apple_modern_hid_static_config_xml, xml_len);
    bootkc[xml_off + xml_len] = 0;
    stl_le_p(bootkc + gsc_off + 4, stub_b);
    return true;
}
