/* Modern SPRR permission state, adapted from qemu-sptm 2867d847.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef ARM_MODERN_SPRR_H
#define ARM_MODERN_SPRR_H

#include <stdbool.h>
#include <stdint.h>

typedef struct AppleModernSPRRState {
    uint64_t config_el[3];
    uint64_t pperm_el[3];
    uint64_t uperm_el0;
} AppleModernSPRRState;

struct ArchCPU;
struct Error;
bool arm_apple_modern_sprr_validate(struct ArchCPU *cpu, struct Error **errp);
void arm_register_apple_modern_sprr(struct ArchCPU *cpu);
void arm_register_apple_modern_sprr_aliases(struct ArchCPU *cpu);
bool apple_modern_sprr_enabled(const AppleModernSPRRState *state);
int apple_modern_sprr_prot(const AppleModernSPRRState *state, unsigned el,
                           bool guarded, uint64_t descriptor);

#endif
