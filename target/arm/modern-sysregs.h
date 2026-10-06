/*
 * Darwin-VM-compatible Apple implementation register stores.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef ARM_MODERN_SYSREGS_H
#define ARM_MODERN_SYSREGS_H

#include <stdbool.h>
#include <stdint.h>

/* Capacity; the generated table size is checked against it at build time. */
#define APPLE_MODERN_OPAQUE_MAX 256

typedef struct AppleModernSysregState {
    uint64_t opaque[APPLE_MODERN_OPAQUE_MAX];
    uint64_t pmc[2];
} AppleModernSysregState;

struct ArchCPU;
struct Error;
bool arm_apple_modern_sysregs_validate(struct ArchCPU *cpu, struct Error **errp);
void arm_register_apple_modern_sysregs(struct ArchCPU *cpu);
void arm_register_apple_modern_sysreg_aliases(struct ArchCPU *cpu);
/* Board-supplied value for a store, by register name; false if absent. */
bool arm_apple_modern_sysreg_set(struct ArchCPU *cpu, const char *name,
                                 uint64_t value);

#endif
