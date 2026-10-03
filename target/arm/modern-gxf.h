/*
 * Experimental modern Apple GXF register state.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This is a register interface, not an implementation of guarded execution.
 */
#ifndef ARM_MODERN_GXF_H
#define ARM_MODERN_GXF_H

#include <stdint.h>
#include <stdbool.h>

typedef struct AppleModernGXFState {
    uint64_t currentg;
    uint64_t config_el[3];
    uint64_t entry_el[3];
    uint64_t pabentry_el[3];
    uint64_t sp_gl[3];
    uint64_t tpidr_gl[3];
    uint64_t vbar_gl[3];
    uint64_t spsr_gl[3];
    uint64_t aspsr_gl[3];
    uint64_t esr_gl[3];
    uint64_t elr_gl[3];
    uint64_t far_gl[3];
} AppleModernGXFState;

enum { APPLE_MODERN_GXF_ALIAS_COUNT = 9 };

/* QEMU's architecture CPU object is named ArchCPU, typedef'd as ARMCPU. */
struct ArchCPU;
struct Error;
bool arm_apple_modern_gxf_validate(struct ArchCPU *cpu, struct Error **errp);
void arm_register_apple_modern_gxf(struct ArchCPU *cpu);
void arm_register_apple_modern_gxf_aliases(struct ArchCPU *cpu);

#endif
