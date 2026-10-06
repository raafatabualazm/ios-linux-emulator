#!/usr/bin/env python3
"""Test production modern SPRR tables and the actual PTW regime helper.

Compiles modern-sprr.c directly in its standalone mode and extracts the real
PTW helper, MMU enumeration and regime predicates. The expected masks are
explicit independent tables. No firmware or guest page-table walk executes.
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
#include "modern-sprr.h"
#define assert_not_reached() assert(false)
typedef struct CPUARMState {
    AppleModernSPRRState modern_sprr;
    uint64_t legacy_canary[8], currentg;
    unsigned current_el;
} CPUARMState;
/* Fixture view of the CPU state predicates used by the production walker. */
static inline int arm_current_el(CPUARMState *env) { return env->current_el; }
static inline bool arm_is_modern_guarded(CPUARMState *env)
{
    return env->currentg & 1;
}
'''


TESTS = r'''
static const unsigned ordinary[16] = {0,5,1,3,0,5,1,0,0,4,1,3,0,5,1,3};
static const unsigned guarded[16] = {0,0,0,0,5,5,5,5,1,1,1,1,3,3,3,3};
static unsigned checks;
#define CHECK(expression) do { checks++; assert(expression); } while (0)

static uint64_t descriptor(unsigned selector)
{
    return ((uint64_t)(selector & 3) << 53) |
           ((uint64_t)(selector >> 2) << 6);
}

static uint64_t permissions(unsigned selector, unsigned nibble)
{
    uint64_t base = UINT64_C(0xfedcba9876543210);
    return (base & ~(UINT64_C(15) << (4 * selector))) |
           ((uint64_t)nibble << (4 * selector));
}

static void test_enable(void)
{
    const uint64_t configs[] = {0,1,2,UINT64_C(0x8000000000000000),UINT64_MAX};
    for (unsigned one = 0; one < 5; one++)
    for (unsigned two = 0; two < 5; two++) {
        AppleModernSPRRState state = {0};
        state.config_el[0] = UINT64_MAX; /* not a canonical enable register */
        state.config_el[1] = configs[one];
        state.config_el[2] = configs[two];
        CHECK(apple_modern_sprr_enabled(&state) == (one != 0 || two != 0));
    }
}

static void test_masks(void)
{
    for (unsigned selector = 0; selector < 16; selector++)
    for (unsigned nibble = 0; nibble < 16; nibble++)
    for (unsigned el = 0; el < 3; el++)
    for (unsigned gl = 0; gl < 2; gl++) {
        AppleModernSPRRState state = {
            .config_el = {UINT64_MAX, 2, 0},
            .pperm_el = {UINT64_MAX, UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x4444444444444444)},
            .uperm_el0 = UINT64_C(0xbbbbbbbbbbbbbbbb),
        };
        uint64_t value = permissions(selector, nibble);
        if (el) state.pperm_el[el] = value;
        else state.uperm_el0 = value;
        AppleModernSPRRState saved = state;
        /* Guarded EL0 selects UPERM through the guarded table (Darwin). */
        unsigned expected = gl ? guarded[nibble] : ordinary[nibble];
        uint64_t pte = descriptor(selector);
        CHECK((unsigned)apple_modern_sprr_prot(&state, el, gl, pte) == expected);
        /* Every descriptor bit outside the four selector bits is irrelevant. */
        uint64_t selector_mask = (UINT64_C(3) << 53) | (UINT64_C(3) << 6);
        CHECK((unsigned)apple_modern_sprr_prot(&state, el, gl, pte | ~selector_mask) == expected);
        CHECK(memcmp(&state, &saved, sizeof(state)) == 0);
        CHECK((expected & 6) != 6); /* never write + execute */
        CHECK(apple_modern_sprr_prot(&state, 3, gl, pte) == 0);
        CHECK(apple_modern_sprr_prot(&state, UINT32_MAX, gl, pte) == 0);
    }
    AppleModernSPRRState zero = {0};
    for (unsigned selector = 0; selector < 16; selector++)
    for (unsigned el = 0; el < 3; el++)
    for (unsigned gl = 0; gl < 2; gl++) {
        CHECK(apple_modern_sprr_prot(&zero, el, gl, descriptor(selector)) == 0);
    }
}

typedef struct Regime {
    ARMMMUIdx index;
    unsigned el;
    bool gl;
} Regime;
static const Regime regimes[] = {
    {ARMMMUIdx_Stage1_E0,0,false},
    {ARMMMUIdx_Stage1_E1,1,false},
    {ARMMMUIdx_Stage1_E1_PAN,1,false},
    {ARMMMUIdx_Stage1_GE1,1,true},
    {ARMMMUIdx_Stage1_GE1_PAN,1,true},
    {ARMMMUIdx_E10_0,0,false},
    {ARMMMUIdx_E20_0,0,false},
    {ARMMMUIdx_E2,2,false},
    {ARMMMUIdx_GE2,2,true},
    {ARMMMUIdx_E20_2,2,false},
    {ARMMMUIdx_E20_2_PAN,2,false},
    {ARMMMUIdx_GE20_2,2,true},
    {ARMMMUIdx_GE20_2_PAN,2,true},
    {ARMMMUIdx_E3,3,false},
    {ARMMMUIdx_GE3,3,true},
};

static void test_regimes(void)
{
    for (unsigned r = 0; r < sizeof(regimes) / sizeof(regimes[0]); r++)
    for (unsigned selector = 0; selector < 16; selector++)
    for (unsigned nibble = 0; nibble < 16; nibble++)
    for (unsigned current = 0; current < 4; current++)
    for (unsigned g = 0; g < 2; g++) {
        CPUARMState env = {0};
        const Regime *regime = &regimes[r];
        env.modern_sprr.uperm_el0 = permissions(selector, (nibble + 5) & 15);
        env.modern_sprr.pperm_el[1] = permissions(selector, (nibble + 11) & 15);
        env.modern_sprr.pperm_el[2] = permissions(selector, (nibble + 7) & 15);
        if (!regime->el) env.modern_sprr.uperm_el0 = permissions(selector, nibble);
        else if (regime->el < 3) env.modern_sprr.pperm_el[regime->el] = permissions(selector, nibble);
        env.current_el = current;
        env.currentg = g ? current | 1 : current & ~1u;
        memset(env.legacy_canary, 0x9b, sizeof(env.legacy_canary));
        CPUARMState saved = env;
        /*
         * User regimes are guarded only while executing at guarded EL0; AT
         * S1E0* from a higher level keeps the ordinary user table.
         */
        bool gl = regime->gl || (regime->el == 0 && current == 0 && g);
        unsigned expected = regime->el == 3 ? 0 :
                            (gl ? guarded[nibble] : ordinary[nibble]);
        CHECK((unsigned)modern_sprr_regime_prot(&env, regime->index, true, descriptor(selector)) == expected);
        CHECK(modern_sprr_regime_prot(&env, regime->index, false, descriptor(selector)) == 0);
        CHECK(memcmp(&env, &saved, sizeof(env)) == 0);
    }
}

int main(void)
{
    CHECK((unsigned)ARMMMUIdx_Stage1_GE1 == 0x43);
    CHECK((unsigned)ARMMMUIdx_Stage1_GE1_PAN == 0x44);
    test_enable();
    test_masks();
    test_regimes();
    printf("%u production SPRR permission and PTW regime checks passed (ASan+UBSan)\n", checks);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--negative-oracle', action='store_true')
    args = parser.parse_args()
    ptw = (args.repo / 'target/arm/ptw.c').read_text()
    internals = (args.repo / 'target/arm/internals.h').read_text()
    cpu_header = (args.repo / 'target/arm/cpu.h').read_text()
    production = function(ptw, 'modern_sprr_regime_prot')
    predicates = ''.join(function(internals, name) for name in
                         ('arm_mmu_idx_is_guarded', 'regime_is_user', 'regime_el'))
    names = ('A_GXF', 'A', 'NOTLB', 'M', 'M_PRIV', 'M_NEGPRI', 'M_S')
    macros = '\n'.join(re.search(r'^#define ARM_MMU_IDX_' + name + r'\s+[^\n]+',
                                 cpu_header, re.M).group(0) for name in names) + '\n'
    enum_start = cpu_header.index('typedef enum ARMMMUIdx {')
    enum_end = cpu_header.index('} ARMMMUIdx;', enum_start) + len('} ARMMMUIdx;')
    enumeration = cpu_header[enum_start:enum_end] + '\n'
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    variants = [('production', production)]
    if args.negative_oracle:
        guarded = re.search(r'bool guarded = [^;]+;', production)
        if not guarded or 'ARMMMUIdx_Stage1_GE1_PAN' not in guarded.group(0):
            raise RuntimeError('Missing explicit guarded NOTLB regime selection')
        variants.append(('bit-only-guarded-oracle', production.replace(guarded.group(0),
                          'bool guarded = arm_mmu_idx_is_guarded(mmu_idx);')))
        raw_call = 'guarded, descriptor);'
        if production.count(raw_call) != 1:
            raise RuntimeError('Missing raw descriptor argument to permission helper')
        override = 'arm_is_modern_guarded(env)) {\n        guarded = true;'
        if production.count(override) != 1:
            raise RuntimeError('Missing guarded EL0 permission selection')
        variants.append(('ordinary-only-EL0-oracle', production.replace(override,
                          'arm_is_modern_guarded(env)) {\n        guarded = false;')))
        variants.append(('folded-XN-selector-oracle', production.replace(raw_call,
                          'guarded, descriptor | (UINT64_C(1) << 53));')))
    with tempfile.TemporaryDirectory(prefix='apple-sprr-unit-') as directory:
        fixture = Path(directory) / 'fixture.c'
        binary = Path(directory) / 'fixture'
        for label, callback in variants:
            fixture.write_text(PRELUDE + macros + enumeration + predicates + callback + TESTS)
            subprocess.run([args.cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-DAPPLE_MODERN_SPRR_STANDALONE',
                            '-fno-omit-frame-pointer', '-fsanitize=address,undefined',
                            '-I', str(args.repo / 'target/arm'), str(fixture),
                            str(args.repo / 'target/arm/modern-sprr.c'), '-o', str(binary)],
                           check=True, timeout=60)
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    env=os.environ, timeout=30)
            if label == 'production':
                print(result.stdout, end='')
                if result.returncode:
                    print(result.stderr, end='')
                    raise SystemExit(result.returncode)
            else:
                if not result.returncode or 'Assertion' not in result.stderr:
                    raise RuntimeError(label + ' was not rejected')
                print(label + ' rejected by independent permission-mask assertion')


if __name__ == '__main__':
    main()
