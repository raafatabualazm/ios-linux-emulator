#!/usr/bin/env python3
"""Record MMU indices chosen by the production A64 AT callback.

The fixture extracts ats_write64, the guarded state predicates and the actual
A-profile MMU enumeration. Only the downstream translation request is replaced
by a recorder; this test does not perform page-table walks or execute firmware.
It checks ordinary, modern and legacy namespaces against explicit expected
index tables, including user operations, VHE and PAN, and rejects the old
legacy-only predicate as a negative oracle.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile


def function(source, name):
    match = re.search(r'^[^\n;{}]*\b' + re.escape(name) +
                      r'\([^;{}]*?\)\n\{', source, re.M)
    if not match:
        raise RuntimeError('Missing production function ' + name)
    position, depth = match.end(), 1
    while depth:
        depth += (source[position] == '{') - (source[position] == '}')
        position += 1
    return source[match.start():position] + '\n'


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define PAGE_READ 1
#define PAGE_WRITE 2
#define HCR_E2H (UINT64_C(1) << 34)
#define HCR_TGE (UINT64_C(1) << 27)
#define ARM_FEATURE_GXF 1
#define assert_not_reached() assert(false)
typedef enum { ARMSS_NonSecure, ARMSS_Secure, ARMSS_Root } ARMSecuritySpace;
typedef struct ArchCPU { bool apple_modern_guarded; } ARMCPU;
typedef struct CPUARMState {
    ARMCPU cpu;
    struct { uint64_t gxf_status_el[4]; } gxf;
    struct { uint64_t currentg; } modern_gxf;
    struct { uint64_t par_el[4]; } cp15;
    uint64_t hcr;
    unsigned features, current_el;
    bool pan;
    ARMSecuritySpace space, below_space;
} CPUARMState;
typedef struct ARMCPRegInfo { unsigned opc1, opc2, crm; } ARMCPRegInfo;
static ARMCPU *env_archcpu(CPUARMState *env) { return &env->cpu; }
static bool arm_feature(CPUARMState *env, unsigned bit) { return env->features & bit; }
static unsigned arm_current_el(CPUARMState *env) { return env->current_el; }
static bool arm_pan_enabled(CPUARMState *env) { return env->pan; }
static uint64_t arm_hcr_el2_eff(CPUARMState *env) { return env->hcr; }
static ARMSecuritySpace arm_security_space(CPUARMState *env) { return env->space; }
static ARMSecuritySpace arm_security_space_below_el3(CPUARMState *env) { return env->below_space; }
'''


RECORDER = r'''
typedef struct RecordedTranslation {
    CPUARMState *env;
    uint64_t value;
    unsigned prot_check, calls;
    ARMMMUIdx mmu_idx;
    ARMSecuritySpace space;
} RecordedTranslation;
static RecordedTranslation recorded;
static const uint64_t test_par = UINT64_C(0x0123456789abcdef);
static uint64_t do_ats_write(CPUARMState *env, uint64_t value,
                             unsigned prot_check, ARMMMUIdx mmu_idx,
                             ARMSecuritySpace space)
{
    recorded.env = env;
    recorded.value = value;
    recorded.prot_check = prot_check;
    recorded.mmu_idx = mmu_idx;
    recorded.space = space;
    recorded.calls++;
    return test_par;
}
'''


TESTS = r'''
typedef struct Operation {
    const char *name;
    ARMCPRegInfo ri;
    bool pan_variant, el3;
    /* Ordered by HCR.{TGE,E2H} = 00, 01, 10, 11. */
    unsigned normal[4], guarded[4], normal_pan[4], guarded_pan[4];
} Operation;
static const Operation operations[] = {
    { "S1E1R",  {0,0,8}, false,false, {65,65,65,35}, {67,67,67,51} },
    { "S1E1W",  {0,1,8}, false,false, {65,65,65,35}, {67,67,67,51} },
    { "S1E1RP", {0,0,9}, true, false, {65,65,65,35}, {67,67,67,51},
                                       {66,66,66,37}, {68,68,68,53} },
    { "S1E1WP", {0,1,9}, true, false, {65,65,65,35}, {67,67,67,51},
                                       {66,66,66,37}, {68,68,68,53} },
    { "S1E2R",  {4,0,8}, false,false, {38,35,38,35}, {54,51,54,51} },
    { "S1E2W",  {4,1,8}, false,false, {38,35,38,35}, {54,51,54,51} },
    { "S1E3R",  {6,0,8}, false,true,  {39,39,39,39}, {55,55,55,55} },
    { "S1E3W",  {6,1,8}, false,true,  {39,39,39,39}, {55,55,55,55} },
    { "S1E0R",  {0,2,8}, false,false, {64,64,64,33}, {64,64,64,33} },
    { "S1E0W",  {0,3,8}, false,false, {64,64,64,33}, {64,64,64,33} },
    { "S12E1R", {4,4,8}, false,false, {34,34,34,35}, {50,50,50,51} },
    { "S12E1W", {4,5,8}, false,false, {34,34,34,35}, {50,50,50,51} },
    { "S12E0R", {4,6,8}, false,false, {32,32,32,33}, {32,32,32,33} },
    { "S12E0W", {4,7,8}, false,false, {32,32,32,33}, {32,32,32,33} },
};
int main(void)
{
    unsigned checks = 0, calls = 0;
    /* Feature/property/current-state cross-products catch namespace leaks. */
    for (unsigned modern_option = 0; modern_option < 2; modern_option++)
    for (unsigned modern_state = 0; modern_state < 4; modern_state++)
    for (unsigned legacy_feature = 0; legacy_feature < 2; legacy_feature++)
    for (unsigned legacy_state = 0; legacy_state < 4; legacy_state++)
    for (unsigned hcr = 0; hcr < 4; hcr++)
    for (unsigned pan = 0; pan < 2; pan++)
    for (unsigned op = 0; op < sizeof(operations) / sizeof(operations[0]); op++) {
        const Operation *operation = &operations[op];
        CPUARMState env = {0};
        env.cpu.apple_modern_guarded = modern_option;
        env.modern_gxf.currentg = modern_state;
        env.features = legacy_feature ? ARM_FEATURE_GXF : 0;
        env.current_el = 2;
        env.gxf.gxf_status_el[2] = legacy_state;
        env.hcr = ((hcr & 1) ? HCR_E2H : 0) | ((hcr & 2) ? HCR_TGE : 0);
        env.pan = pan;
        env.space = ARMSS_Root;
        env.below_space = ARMSS_NonSecure;
        env.cp15.par_el[0] = UINT64_C(0xa0a0);
        env.cp15.par_el[2] = UINT64_C(0xb2b2);
        bool guarded = (modern_option && (modern_state & 1)) ||
                       (legacy_feature && (legacy_state & 1));
        const unsigned *expected_table;
        if (operation->pan_variant && pan) {
            expected_table = guarded ? operation->guarded_pan : operation->normal_pan;
        } else {
            expected_table = guarded ? operation->guarded : operation->normal;
        }
        uint64_t value = UINT64_C(0xf123456789abcdef) ^ op;
        memset(&recorded, 0, sizeof(recorded));
        ats_write64(&env, &operation->ri, value);
        calls++;
        checks++; assert(recorded.calls == 1 && recorded.env == &env);
        checks++; assert((unsigned)recorded.mmu_idx == expected_table[hcr]);
        checks++; assert(recorded.prot_check == ((operation->ri.opc2 & 1) ? PAGE_WRITE : PAGE_READ));
        checks++; assert(recorded.value == value);
        checks++; assert(recorded.space == (operation->el3 ? ARMSS_Root : ARMSS_NonSecure));
        checks++; assert(env.cp15.par_el[1] == test_par);
        checks++; assert(env.cp15.par_el[0] == UINT64_C(0xa0a0) && env.cp15.par_el[2] == UINT64_C(0xb2b2));
        checks++; assert(env.modern_gxf.currentg == modern_state && env.gxf.gxf_status_el[2] == legacy_state);
    }
    printf("%u recorded production A64 AT checks passed across %u callback calls (ASan+UBSan)\n", checks, calls);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--negative-oracle', action='store_true')
    parser.add_argument('--baseline-ref', help='Also check all source outside the A64 callback is unchanged')
    args = parser.parse_args()
    source = (args.repo / 'target/arm/tcg/cpregs-at.c').read_text()
    internals = (args.repo / 'target/arm/internals.h').read_text()
    cpu_header = (args.repo / 'target/arm/cpu.h').read_text()
    production = function(source, 'ats_write64')
    predicates = ''.join(function(internals, name) for name in
                         ('arm_is_guarded', 'arm_is_modern_guarded', 'arm_is_any_guarded'))
    macros = '\n'.join(re.findall(r'^#define ARM_MMU_IDX_(?:A_GXF|A|NOTLB)\s+[^\n]+',
                                   cpu_header, re.M)) + '\n'
    enum_start = cpu_header.index('typedef enum ARMMMUIdx {')
    enum_end = cpu_header.index('    /*\n     * M-profile.', enum_start)
    enumeration = cpu_header[enum_start:enum_end] + '} ARMMMUIdx;\n'
    if args.baseline_ref:
        baseline = subprocess.run(['git', '-C', str(args.repo), 'show',
                                   args.baseline_ref + ':target/arm/tcg/cpregs-at.c'],
                                  check=True, capture_output=True, text=True, timeout=30).stdout
        baseline_callback = function(baseline, 'ats_write64')
        if source.replace(production, 'A64_CALLBACK\n') != baseline.replace(baseline_callback, 'A64_CALLBACK\n'):
            raise RuntimeError('Unexpected source change outside the owned A64 callback')
        print('A32 AT callbacks and all source outside ats_write64 unchanged from ' + args.baseline_ref)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    variants = [('production', production)]
    if args.negative_oracle:
        predicate = 'arm_is_any_guarded(env)'
        if production.count(predicate) != 1:
            raise RuntimeError('Missing isolated A64 modern guarded predicate')
        variants.append(('legacy-only-oracle', production.replace(predicate, 'arm_is_guarded(env)')))
    with tempfile.TemporaryDirectory(prefix='apple-at-unit-') as directory:
        fixture = Path(directory) / 'fixture.c'
        binary = Path(directory) / 'fixture'
        for label, callback in variants:
            fixture.write_text(PRELUDE + macros + enumeration + predicates + RECORDER + callback + TESTS)
            subprocess.run([args.cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-Wno-missing-field-initializers', '-Wno-unused-function',
                            '-fno-omit-frame-pointer', '-fsanitize=address,undefined',
                            str(fixture), '-o', str(binary)], check=True, timeout=60)
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    env=os.environ, timeout=30)
            if label == 'production':
                print(result.stdout, end='')
                if result.returncode:
                    print(result.stderr, end='')
                    raise SystemExit(result.returncode)
            else:
                if not result.returncode or 'Assertion' not in result.stderr:
                    raise RuntimeError('Legacy-only AT oracle was not rejected')
                print('Legacy-only AT selection oracle rejected by recorded-index assertion')


if __name__ == '__main__':
    main()
