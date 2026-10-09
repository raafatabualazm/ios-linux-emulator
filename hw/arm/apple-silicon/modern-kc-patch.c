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
    /* The two anchors describe different functions; they must not overlap. */
    if (strategy + 16 > blockcount && blockcount + 20 > strategy) {
        error_setg(errp, "md0-width-compat: the two anchors overlap at "
                   "0x%" PRIx64 " and 0x%" PRIx64 "; refusing to patch",
                   strategy, blockcount);
        return false;
    }

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
