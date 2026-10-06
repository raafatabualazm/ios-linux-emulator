#!/usr/bin/env python3
"""Sanitize production SP-bank/GEXIT code for legacy and modern profiles.

QEMU logging, execution hooks and exception delivery are small stubs. Bank
selection, saved-state validation and GEXIT transitions are production code.
The separate owned-ROM gate tests decoding and real CPU exception routing.
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def extract(source, marker):
    start = source.index(marker)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    return source[start:end] + '\n'


PRELUDE = r'''
#include <assert.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "modern-gxf.h"
#define ARM_FEATURE_GXF 1
#define PSTATE_SP 1
#define PSTATE_nRW 16
#define PSTATE_SS (1U << 21)
#define CPSR_M 31
#define ARM_CPU_MODE_USR 16
#define ARM_CPU_MODE_FIQ 17
#define ARM_CPU_MODE_IRQ 18
#define ARM_CPU_MODE_SVC 19
#define ARM_CPU_MODE_MON 22
#define ARM_CPU_MODE_ABT 23
#define ARM_CPU_MODE_HYP 26
#define ARM_CPU_MODE_UND 27
#define ARM_CPU_MODE_SYS 31
#define EXCP_UDEF 1
#define GETPC() 0
#define HELPER(name) helper_##name
#define qemu_log_mask(...) ((void)0)
typedef struct ArchCPU ARMCPU;
typedef struct CPUARMState {
    ARMCPU *owner;
    uint64_t features, pc, sp_el[4], xregs[32];
    uint32_t pstate;
    AppleModernGXFState modern_gxf;
    struct {
        uint64_t gxf_status_el[4], sp_gl[4], spsr_gl[4], elr_gl[4];
    } gxf;
} CPUARMState;
struct ArchCPU { CPUARMState env; bool apple_modern_guarded; int isar; };
static ARMCPU *env_archcpu(CPUARMState *env) { return env->owner; }
static int arm_current_el(CPUARMState *env) { return (env->pstate >> 2) & 3; }
static bool arm_feature(CPUARMState *env, int flag) { return env->features & flag; }
static uint32_t extract32(uint32_t n, int first, int count) {
    return (n >> first) & ((1U << count) - 1);
}
static uint32_t aarch64_pstate_valid_mask(const int *isar) {
    (void)isar; return UINT32_MAX;
}
static void pstate_write(CPUARMState *env, uint32_t value) { env->pstate = value; }
static bool arm_generate_debug_exceptions(CPUARMState *env) { (void)env; return false; }
static bool arm_singlestep_active(CPUARMState *env) { (void)env; return true; }
static void helper_rebuild_hflags_a64(CPUARMState *env, int el) { (void)env; (void)el; }
static void arm_clear_exclusive(CPUARMState *env) { (void)env; }
static unsigned syn_uncategorized(void) { return 0; }
static jmp_buf exception;
static void raise_exception_ra(CPUARMState *env, int index, unsigned syndrome,
                               int el, uintptr_t pc) {
    (void)env; (void)syndrome; (void)el; (void)pc;
    assert(index == EXCP_UDEF); longjmp(exception, 1);
}
'''

TESTS = r'''
int main(void) {
    ARMCPU cpu = {0};
    CPUARMState *env = &cpu.env;
    AppleModernGXFState preserved;
    env->owner = &cpu;
    env->pstate = 0x3c5;
    env->features = ARM_FEATURE_GXF;
    env->gxf.gxf_status_el[1] = 1;
    memset(&env->modern_gxf, 0xa5, sizeof(env->modern_gxf));
    preserved = env->modern_gxf;
    env->xregs[31] = 0x111;
    env->sp_el[1] = 0x222;
    env->gxf.sp_gl[1] = 0x333;
    env->gxf.spsr_gl[1] = 0x3c5;
    env->gxf.elr_gl[1] = 0x444;
    assert(arm_is_guarded(env) && !arm_is_modern_guarded(env));
    helper_gexit(env);
    assert(env->gxf.sp_gl[1] == 0x111);
    assert(env->xregs[31] == 0x222 && env->sp_el[1] == 0x222);
    assert(env->pc == 0x444 && env->pstate == 0x3c5);
    assert(!arm_is_any_guarded(env));
    assert(memcmp(&preserved, &env->modern_gxf, sizeof(preserved)) == 0);
    env->gxf.gxf_status_el[1] = 1;
    env->features = 0;
    env->xregs[31] = 0x555;
    aarch64_save_sp(env, 1);
    assert(env->sp_el[1] == 0x555 && env->gxf.sp_gl[1] == 0x111);
    aarch64_restore_sp(env, 1);
    assert(env->xregs[31] == 0x555);

    cpu.apple_modern_guarded = true;
    memset(&env->modern_gxf, 0, sizeof(env->modern_gxf));
    env->modern_gxf.currentg = 1;
    env->modern_gxf.spsr_gl[1] = 0x3c5;
    env->modern_gxf.aspsr_gl[1] = 0;
    env->modern_gxf.elr_gl[1] = 0x666;
    env->xregs[31] = 0x777;
    helper_gexit(env);
    assert(env->modern_gxf.sp_gl[1] == 0x777);
    assert(env->modern_gxf.currentg == 0 && env->pc == 0x666);
    assert(env->xregs[31] == 0x555 && env->sp_el[1] == 0x555);
    assert(env->gxf.gxf_status_el[1] == 1 && env->gxf.sp_gl[1] == 0x111);

    env->modern_gxf.currentg = 1;
    env->modern_gxf.aspsr_gl[1] = 1;
    env->xregs[31] = 0x888;
    helper_gexit(env);
    assert(env->modern_gxf.currentg == 1 && env->xregs[31] == 0x888);
    assert(env->sp_el[1] == 0x555);
    env->pstate &= ~PSTATE_SP;
    env->xregs[31] = 0x999;
    aarch64_save_sp(env, 1);
    assert(env->sp_el[0] == 0x999 && env->modern_gxf.sp_gl[1] == 0x888);
    env->xregs[31] = 0;
    aarch64_restore_sp(env, 1);
    assert(env->xregs[31] == 0x999);
    env->pstate = 0x3c5;

    for (unsigned test = 0; test < 4; test++) {
        env->modern_gxf.currentg = 1;
        env->modern_gxf.aspsr_gl[1] = test == 0 ? 2 : 0;
        env->modern_gxf.spsr_gl[1] = test == 1 ? 0x3c9 :
                                   test == 2 ? 0x3d3 : 0x3c5;
        if (test == 3) { env->modern_gxf.currentg = 0; }
        CPUARMState before = *env;
        if (!setjmp(exception)) {
            helper_gexit(env);
            assert(!"Malformed modern GEXIT did not raise UNDEF");
        }
        assert(memcmp(&before, env, sizeof(before)) == 0);
    }
    puts("Production legacy/modern SP and GEXIT state checks passed");
    return 0;
}
'''


def main():
    repo = Path(__file__).resolve().parents[1]
    internals = (repo / 'target/arm/internals.h').read_text()
    helper = (repo / 'target/arm/tcg/helper-a64.c').read_text()
    code = PRELUDE
    for name in ('arm_is_guarded', 'arm_is_modern_guarded', 'arm_is_any_guarded',
                 'aarch64_save_sp', 'aarch64_restore_sp'):
        code += extract(internals, f'static inline {"void" if name.startswith("aarch64") else "bool"} {name}(')
    code += extract(helper, 'static int el_from_spsr(')
    code += extract(helper, 'void HELPER(gexit)(')
    code += TESTS
    with tempfile.TemporaryDirectory(prefix='apple-guarded-state-') as directory:
        cfile = Path(directory) / 'test.c'
        binary = Path(directory) / 'test'
        cfile.write_text(code)
        command = shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=c11', '-Wall', '-Wextra', '-Werror', '-g',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
            '-I', str(repo / 'target/arm'), str(cfile), '-o', str(binary)]
        subprocess.run(command, check=True)
        # The fixture allocates no heap objects; LSAN cannot attach under the
        # current ptrace sandbox. ASan and UBSan remain enabled.
        subprocess.run([str(binary)], check=True,
                       env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0:abort_on_error=1'})


if __name__ == '__main__':
    main()
