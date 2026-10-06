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
#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "hw/arm/apple-silicon/modern-kc-patch.h"

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
    uint32_t first;
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
