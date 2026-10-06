/*
 * Modern SPRR registers and permission tables.
 * Reference: qemu-sptm 2867d847, get_S1prot_sprr and dumpregs.py.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * CONFIG/UPERM/PPERM have real permission effects in the page walker.
 * Hardware mask/lock controls are not approximated. EL0 may read UPERM but
 * writes remain unsupported until their permission mask is implemented.
 */
#ifdef APPLE_MODERN_SPRR_STANDALONE
#include <stddef.h>
#include <stdint.h>
#define PAGE_READ 1
#define PAGE_WRITE 2
#define PAGE_EXEC 4
#else
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "cpu.h"
#include "internals.h"
#include "exec/cputlb.h"
#include "exec/page-protection.h"
#endif
#include "modern-sprr.h"

bool apple_modern_sprr_enabled(const AppleModernSPRRState *state)
{
    /* This enable rule is Darwin's compatibility model, not a hardware spec. */
    return state->config_el[1] || state->config_el[2];
}

int apple_modern_sprr_prot(const AppleModernSPRRState *state, unsigned el,
                           bool guarded, uint64_t descriptor)
{
    static const uint8_t gl_permissions[16] = {
        0, 0, 0, 0,
        PAGE_READ | PAGE_EXEC, PAGE_READ | PAGE_EXEC,
        PAGE_READ | PAGE_EXEC, PAGE_READ | PAGE_EXEC,
        PAGE_READ, PAGE_READ, PAGE_READ, PAGE_READ,
        PAGE_READ | PAGE_WRITE, PAGE_READ | PAGE_WRITE,
        PAGE_READ | PAGE_WRITE, PAGE_READ | PAGE_WRITE,
    };
    static const uint8_t el_permissions[16] = {
        0, PAGE_READ | PAGE_EXEC, PAGE_READ, PAGE_READ | PAGE_WRITE,
        0, PAGE_READ | PAGE_EXEC, PAGE_READ, 0,
        0, PAGE_EXEC, PAGE_READ, PAGE_READ | PAGE_WRITE,
        0, PAGE_READ | PAGE_EXEC, PAGE_READ, PAGE_READ | PAGE_WRITE,
    };
    unsigned index = ((descriptor >> 53) & 3) |
                     (((descriptor >> 6) & 3) << 2);
    uint64_t permissions;

    /* Unsupported privilege levels fail closed. */
    if (el > 2 || (el == 0 && guarded)) {
        return 0;
    }
    permissions = el ? state->pperm_el[el] : state->uperm_el0;
    index = (permissions >> (4 * index)) & 15;
    return guarded ? gl_permissions[index] : el_permissions[index];
}

#ifndef APPLE_MODERN_SPRR_STANDALONE
bool arm_apple_modern_sprr_validate(ARMCPU *cpu, Error **errp)
{
    if (cpu->apple_modern_sprr &&
        (!cpu->apple_modern_gxf || !cpu->apple_modern_guarded)) {
        error_setg(errp, "apple-modern-sprr requires apple-modern-gxf and "
                   "apple-modern-guarded");
        return false;
    }
    return true;
}

static void modern_sprr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    raw_write(env, ri, value);
    /* EL, GL and user translations share the permission registers. */
    tlb_flush(env_cpu(env));
}

#define SPRR_REG(n, crm_, op2_, member_, rights_) \
    { .name = n, .state = ARM_CP_STATE_AA64, \
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = crm_, .opc2 = op2_, \
      .access = rights_, .resetvalue = 0, .writefn = modern_sprr_write, \
      .raw_readfn = raw_read, .raw_writefn = raw_write, \
      .fieldoffset = offsetof(CPUARMState, modern_sprr.member_) }

static const ARMCPRegInfo modern_sprr_regs[] = {
    SPRR_REG("SPRR_CONFIG_EL1", 1, 0, config_el[1], PL1_RW),
    SPRR_REG("SPRR_CONFIG_EL2", 14, 2, config_el[2], PL2_RW),
    SPRR_REG("SPRR_PPERM_EL1", 1, 6, pperm_el[1], PL1_RW),
    SPRR_REG("SPRR_PPERM_EL2", 1, 7, pperm_el[2], PL2_RW),
    SPRR_REG("SPRR_UPERM_EL0", 1, 5, uperm_el0, PL1_RW | PL0_R),
};
#undef SPRR_REG

void arm_register_apple_modern_sprr(ARMCPU *cpu)
{
    assert(cpu->apple_modern_sprr);
    define_arm_cp_regs(cpu, modern_sprr_regs);
}

#define SPRR_KEY(crm_, op2_) \
    ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP, 15, crm_, 3, 6, op2_)
void arm_register_apple_modern_sprr_aliases(ARMCPU *cpu)
{
    assert(cpu->apple_modern_sprr && cpu->apple_modern_gxf);
    arm_define_vhe_alias(cpu, SPRR_KEY(1, 0), SPRR_KEY(14, 2),
                         SPRR_KEY(15, 4), "SPRR_CONFIG_EL1",
                         "SPRR_CONFIG_EL2", "SPRR_CONFIG_EL12");
    arm_define_vhe_alias(cpu, SPRR_KEY(1, 6), SPRR_KEY(1, 7),
                         SPRR_KEY(15, 7), "SPRR_PPERM_EL1",
                         "SPRR_PPERM_EL2", "SPRR_PPERM_EL12");
}
#undef SPRR_KEY
#endif
