/*
 * Apple modern board: EL0 software-breakpoint (BRK) trace.
 *
 * Read-only observability. Default off. When the opt-in board option
 * el0-trap-trace is set, every AArch64 BRK taken while the guest is at EL0 is
 * reported once on the QEMU side with its immediate, its program counter and
 * the current TTBR0_EL1 (which distinguishes one user address space from
 * another without naming a process).
 *
 * Why this exists: a userspace process that dies with SIGTRAP "sent by exc
 * handler" on arm64 died from EXC_BREAKPOINT, and with no debugger attached the
 * only architectural source of EXC_BREAKPOINT is a BRK instruction. The BRK
 * immediate says which kind of trap it was. The two immediates classified here
 * are read from published LLVM source, see modern-el0-trap.c.
 *
 * Copyright (c) 2026 the Inferno modern-iOS work.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_APPLE_SILICON_MODERN_EL0_TRAP_H
#define HW_ARM_APPLE_SILICON_MODERN_EL0_TRAP_H

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stddef.h>
#include <stdint.h>
#endif

/*
 * Classify a BRK immediate. Returns a short, stable, never-NULL string. Only
 * immediates with a published origin are named; everything else is
 * "unclassified", which is honest rather than convenient.
 */
const char *apple_modern_el0_trap_class(uint32_t imm16);

/*
 * Format one trace line into buf (always NUL-terminated). Returns the number of
 * characters that would have been written, like snprintf.
 */
int apple_modern_el0_trap_format(char *buf, size_t buflen, uint32_t imm16,
                                 uint64_t pc, uint64_t ttbr0);

#endif /* HW_ARM_APPLE_SILICON_MODERN_EL0_TRAP_H */
