/*
 * Modern Apple pointer-authentication status interface.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Primary field/access evidence: Asahi docs 0d1f8917, system-registers.md
 * and system-register-dumps.md. Encodings: m1n1 2460b604, apple_regs.json.
 * APSTS_EL2's name is tentative in that reference. These M1 observations
 * do not specify T8140 reset/initialization timing or an Apple PAC primitive.
 *
 * Bit 0 (M Key Valid) reflects internal readiness; all other bits read zero.
 * The iOS 27 SPTM spins on this bit immediately after enabling its MMU
 * (sptm offset 0x9f5d8) without writing anything that could set it, so the
 * hardware/boot firmware must have established the master key before the
 * handoff. Asahi's M1 dumps read 1 after Apple's loader. The modern boards
 * start the CPU at that handoff, so reset presents the post-loader state:
 * ready. The Apple key transformation itself is not modeled: PAC keeps using
 * the CPU's architectural algorithm with the guest-written keys, and APCTL is
 * a separate store. Guest writes cannot change readiness. Migration of
 * readiness is unsupported (ARM_CP_NO_RAW); it is re-established at reset.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "cpu.h"
#include "cpu-features.h"
#include "internals.h"
#include "modern-apsts.h"

uint64_t apple_modern_apsts_value(const AppleModernAPSTSState *state,
                                 unsigned el)
{
    return (el == 1 || el == 2) && state->ready_el[el] ? 1 : 0;
}

bool arm_apple_modern_apsts_validate(ARMCPU *cpu, Error **errp)
{
    if (!cpu->apple_modern_apsts) {
        return true;
    }
    if (!cpu->apple_modern_gxf || !cpu->apple_modern_guarded) {
        error_setg(errp, "apple-modern-apsts requires apple-modern-gxf and "
                   "apple-modern-guarded");
        return false;
    }
    if (!arm_apple_modern_gxf_validate(cpu, errp)) {
        return false;
    }
    if (!cpu_isar_feature(aa64_pauth, cpu)) {
        error_setg(errp, "apple-modern-apsts requires active pointer "
                   "authentication");
        return false;
    }
    return true;
}

static unsigned modern_apsts_bank(const ARMCPRegInfo *ri)
{
    /* VHE callbacks pass saved, unredirected canonical register metadata. */
    if (ri->type & ARM_CP_ALIAS) {
        ri = ri->opaque;
        assert(ri);
    }
    assert(ri->crm == 12 && (ri->opc2 == 3 || ri->opc2 == 4));
    return ri->opc2 == 4 ? 1 : 2;
}

static uint64_t modern_apsts_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return apple_modern_apsts_value(&env->modern_apsts,
                                    modern_apsts_bank(ri));
}

static void modern_apsts_write_ignored(CPUARMState *env,
                                       const ARMCPRegInfo *ri, uint64_t value)
{
    /*
     * Guest MSR is rejected by the read-only access mask. Raw management
     * callbacks must not create backend readiness either. NO_RAW excludes
     * these registers from raw state lists; this callback is additionally
     * inert if called directly. There is no debugger/QOM readiness setter.
     */
    (void)env;
    (void)ri;
    (void)value;
}

static void modern_apsts_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Handoff state: the master key was generated before the CPU starts. */
    env->modern_apsts.ready_el[modern_apsts_bank(ri)] = true;
}

#define APSTS_REG(n, op2_, rights_) \
    { .name = n, .state = ARM_CP_STATE_AA64, .type = ARM_CP_NO_RAW, \
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 12, .opc2 = op2_, \
      .access = rights_, .readfn = modern_apsts_read, \
      .writefn = modern_apsts_write_ignored, \
      .raw_readfn = modern_apsts_read, \
      .raw_writefn = modern_apsts_write_ignored, \
      .resetfn = modern_apsts_reset }

static const ARMCPRegInfo modern_apsts_regs[] = {
    APSTS_REG("APSTS_EL1", 4, PL1_R),
    APSTS_REG("APSTS_EL2", 3, PL2_R),
};
#undef APSTS_REG

void arm_register_apple_modern_apsts(ARMCPU *cpu)
{
    assert(cpu->apple_modern_apsts);
    define_arm_cp_regs(cpu, modern_apsts_regs);
}

#define APSTS_KEY(crm_, op2_) \
    ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP, 15, crm_, 3, 6, op2_)

void arm_register_apple_modern_apsts_aliases(ARMCPU *cpu)
{
    assert(cpu->apple_modern_apsts && cpu->apple_modern_gxf);
    arm_define_vhe_alias(cpu, APSTS_KEY(12, 4), APSTS_KEY(12, 3),
                         APSTS_KEY(14, 7), "APSTS_EL1", "APSTS_EL2",
                         "APSTS_EL12");
}
#undef APSTS_KEY
