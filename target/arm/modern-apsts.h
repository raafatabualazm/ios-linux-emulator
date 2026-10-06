/*
 * Modern Apple pointer-authentication status interface.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef ARM_MODERN_APSTS_H
#define ARM_MODERN_APSTS_H

#include <stdbool.h>
#include <stdint.h>

typedef struct AppleModernAPSTSState {
    /*
     * Internal backend readiness, never guest-writable. No production backend
     * currently initializes these banks; reset and supported reads report 0.
     * The unused EL0 slot is not an exposed register bank.
     */
    bool ready_el[3];
} AppleModernAPSTSState;

struct ArchCPU;
struct Error;
bool arm_apple_modern_apsts_validate(struct ArchCPU *cpu, struct Error **errp);
void arm_register_apple_modern_apsts(struct ArchCPU *cpu);
void arm_register_apple_modern_apsts_aliases(struct ArchCPU *cpu);
uint64_t apple_modern_apsts_value(const AppleModernAPSTSState *state,
                                 unsigned el);

#endif
