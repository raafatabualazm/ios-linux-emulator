/*
 * Apple modern board: EL0 software-breakpoint (BRK) classification.
 *
 * Read-only observability for the opt-in, default-off board option
 * el0-trap-trace. See include/hw/arm/apple-silicon/modern-el0-trap.h.
 *
 * The immediates named here are read out of published LLVM source, tag
 * llvmorg-21.1.0 (URL and sha256 recorded in the track's sources/ directory):
 *
 *   llvm/lib/Target/AArch64/AArch64InstrInfo.td
 *     "__builtin_trap() uses the BRK instruction on AArch64."
 *     def : Pat<(trap), (BRK 1)>;                      -> imm 0x0001
 *     def : Pat<(debugtrap), (BRK 0xF000)>;            -> imm 0xF000
 *     ubsan_trap_xform: N->getZExtValue() | ('U' << 8)
 *     def : Pat<(ubsantrap ubsan_trap_imm:$kind), ...  -> imm 0x5500..0x55FF
 *
 *   llvm/lib/Target/AArch64/AArch64AsmPrinter.cpp
 *     "brk #<0xc470 + aut key>"
 *     MCInstBuilder(AArch64::BRK).addImm(0xc470 | Key) -> imm 0xC470..0xC473
 *
 * Anything else is reported as "unclassified" together with its raw immediate.
 * No guess is dressed up as a name.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/modern-el0-trap.h"

const char *apple_modern_el0_trap_class(uint32_t imm16)
{
    imm16 &= 0xffff;

    if (imm16 == 0x0001) {
        /* clang __builtin_trap(); Apple's os_crash()/_os_assert() end here. */
        return "builtin-trap";
    }
    if (imm16 == 0xf000) {
        return "debugtrap";
    }
    if ((imm16 & 0xff00) == 0x5500) {
        return "ubsan-trap";
    }
    if (imm16 >= 0xc470 && imm16 <= 0xc473) {
        return "ptrauth-check-fail";
    }
    return "unclassified";
}

int apple_modern_el0_trap_format(char *buf, size_t buflen, uint32_t imm16,
                                 uint64_t pc, uint64_t ttbr0)
{
    imm16 &= 0xffff;
    return snprintf(buf, buflen,
                    "apple-modern: el0-trap brk #0x%04x (%s) pc=0x%016" PRIx64
                    " ttbr0=0x%016" PRIx64,
                    imm16, apple_modern_el0_trap_class(imm16), pc, ttbr0);
}
