/*
 * Experimental modern Apple GXF register banks.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Register encodings are recorded in the pinned Darwin-VM reference. Only
 * register storage and ordinary VHE aliases are implemented here. The
 * separate apple-modern-guarded profile enables CPU entry/exit handling;
 * the separate modern SPRR profile supplies its declared permissions.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "modern-gxf.h"
#include "cpu-features.h"
#include "qapi/error.h"
#include "system/tcg.h"

bool arm_apple_modern_gxf_validate(ARMCPU *cpu, Error **errp)
{
    CPUARMState *env = &cpu->env;

    if (cpu->apple_modern_guarded && !cpu->apple_modern_gxf) {
        error_setg(errp, "apple-modern-guarded requires apple-modern-gxf");
        return false;
    }
    if (!cpu->apple_modern_gxf) {
        return true;
    }
    if (!tcg_enabled() || !arm_feature(env, ARM_FEATURE_AARCH64) ||
        !cpu->has_el2 || !arm_feature(env, ARM_FEATURE_EL2) ||
        cpu->has_el3 || !cpu_isar_feature(aa64_vh, cpu)) {
        error_setg(errp, "apple-modern-gxf requires AArch64 TCG, EL2/VHE "
                   "and has_el3=false");
        return false;
    }
    if (arm_feature(env, ARM_FEATURE_GXF)) {
        error_setg(errp, "apple-modern-gxf cannot be combined with "
                   "legacy Apple GXF");
        return false;
    }
    if (cpu->prop_pauth_noop || !cpu->prop_pauth) {
        error_setg(errp, "apple-modern-gxf requires pauth=true and "
                   "pauth-noop=false");
        return false;
    }
    return true;
}

#define REG(n, el, crm_, opc2_, member, permissions) \
    { .name = n, .state = ARM_CP_STATE_AA64, \
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = crm_, .opc2 = opc2_, \
      .access = permissions, .resetvalue = 0, \
      .fieldoffset = offsetof(CPUARMState, modern_gxf.member[el]) }

#define GL_PAIR(n, opc2_, member) \
    REG(n "_GL1", 1, 10, opc2_, member, PL1_RW), \
    REG(n "_GL2", 2, 11, opc2_, member, PL2_RW)

static const ARMCPRegInfo modern_gxf_regs[] = {
    { .name = "CURRENTG", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 8, .opc2 = 0,
      .access = PL1_R, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, modern_gxf.currentg) },
    REG("GXF_CONFIG_EL1", 1, 1, 2, config_el, PL1_RW),
    REG("GXF_CONFIG_EL2", 2, 1, 4, config_el, PL2_RW),
    REG("GXF_ENTRY_EL1", 1, 8, 1, entry_el, PL1_RW),
    REG("GXF_ENTRY_EL2", 2, 12, 0, entry_el, PL2_RW),
    REG("GXF_PABENTRY_EL1", 1, 8, 2, pabentry_el, PL1_RW),
    REG("GXF_PABENTRY_EL2", 2, 12, 1, pabentry_el, PL2_RW),
    GL_PAIR("SP", 0, sp_gl),
    GL_PAIR("TPIDR", 1, tpidr_gl),
    GL_PAIR("VBAR", 2, vbar_gl),
    GL_PAIR("SPSR", 3, spsr_gl),
    GL_PAIR("ASPSR", 4, aspsr_gl),
    GL_PAIR("ESR", 5, esr_gl),
    GL_PAIR("ELR", 6, elr_gl),
    GL_PAIR("FAR", 7, far_gl),
};

#undef GL_PAIR
#undef REG

void arm_register_apple_modern_gxf(ARMCPU *cpu)
{
    assert(cpu->apple_modern_gxf);
    define_arm_cp_regs(cpu, modern_gxf_regs);
}

#define K(crm, opc2) \
    ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP, 15, crm, 3, 6, opc2)

void arm_register_apple_modern_gxf_aliases(ARMCPU *cpu)
{
    static const struct {
        uint32_t src, dst, alias;
        const char *src_name, *dst_name, *alias_name;
    } aliases[] = {
        { K(1, 2), K(1, 4), K(15, 1),
          "GXF_CONFIG_EL1", "GXF_CONFIG_EL2", "GXF_CONFIG_EL12" },
        { K(8, 1), K(12, 0), K(15, 2),
          "GXF_ENTRY_EL1", "GXF_ENTRY_EL2", "GXF_ENTRY_EL12" },
        { K(8, 2), K(12, 1), K(15, 3),
          "GXF_PABENTRY_EL1", "GXF_PABENTRY_EL2", "GXF_PABENTRY_EL12" },
        { K(10, 2), K(11, 2), K(9, 2),
          "VBAR_GL1", "VBAR_GL2", "VBAR_GL12" },
        { K(10, 3), K(11, 3), K(9, 3),
          "SPSR_GL1", "SPSR_GL2", "SPSR_GL12" },
        { K(10, 4), K(11, 4), K(9, 4),
          "ASPSR_GL1", "ASPSR_GL2", "ASPSR_GL12" },
        { K(10, 5), K(11, 5), K(9, 5),
          "ESR_GL1", "ESR_GL2", "ESR_GL12" },
        { K(10, 6), K(11, 6), K(9, 6),
          "ELR_GL1", "ELR_GL2", "ELR_GL12" },
        { K(10, 7), K(11, 7), K(9, 7),
          "FAR_GL1", "FAR_GL2", "FAR_GL12" },
    };
    size_t i;

    assert(cpu->apple_modern_gxf);
    QEMU_BUILD_BUG_ON(ARRAY_SIZE(aliases) != APPLE_MODERN_GXF_ALIAS_COUNT);
    for (i = 0; i < ARRAY_SIZE(aliases); i++) {
        arm_define_vhe_alias(cpu, aliases[i].src, aliases[i].dst,
                            aliases[i].alias, aliases[i].src_name,
                            aliases[i].dst_name, aliases[i].alias_name);
    }
}

#undef K
