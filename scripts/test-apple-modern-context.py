#!/usr/bin/env python3
"""Check the production E2H ASID-change TLB flush mask with recorded callbacks.

Extracts the actual write callback and uses a small CPU/register fixture. No
firmware, page-table failure, protected-memory transition or guest patch is
involved. Legacy mask selection is checked alongside shared modern EL/GL
architectural-bank invalidation.
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
#define HCR_E2H (UINT64_C(1) << 34)
#define ARMMMUIdxBit_E20_0 (1U << 1)
#define ARMMMUIdxBit_E20_2 (1U << 3)
#define ARMMMUIdxBit_E20_2_PAN (1U << 5)
#define ARMMMUIdxBit_GE20_2 (1U << 19)
#define ARMMMUIdxBit_GE20_2_PAN (1U << 21)
typedef struct ArchCPU { bool apple_modern_guarded; } ARMCPU;
typedef struct CPUARMState {
    uint64_t reg, hcr;
    bool legacy_gl, modern_gl;
    ARMCPU cpu;
    unsigned flush_count;
    uint32_t flush_mask;
} CPUARMState;
typedef struct ARMCPRegInfo { unsigned unused; } ARMCPRegInfo;
static ARMCPU *env_archcpu(CPUARMState *env) { return &env->cpu; }
static CPUARMState *env_cpu(CPUARMState *env) { return env; }
static uint64_t arm_hcr_el2_eff(CPUARMState *env) { return env->hcr; }
static bool arm_is_guarded(CPUARMState *env) { return env->legacy_gl; }
static uint64_t raw_read(CPUARMState *env,const ARMCPRegInfo *ri) { (void)ri;return env->reg; }
static void raw_write(CPUARMState *env,const ARMCPRegInfo *ri,uint64_t value) { (void)ri;env->reg=value; }
static uint64_t extract64(uint64_t value,unsigned offset,unsigned bits) { return (value>>offset)&((UINT64_C(1)<<bits)-1); }
static void tlb_flush_by_mmuidx(CPUARMState *env,uint32_t mask) { env->flush_count++;env->flush_mask=mask; }
'''

TESTS = r'''
int main(void) {
    unsigned checks=0;
    ARMCPRegInfo ri={0};
    for (unsigned modern=0;modern<2;modern++)
    for (unsigned modern_gl=0;modern_gl<2;modern_gl++)
    for (unsigned legacy_gl=0;legacy_gl<2;legacy_gl++)
    for (unsigned e2h=0;e2h<2;e2h++)
    for (unsigned asid_change=0;asid_change<2;asid_change++) {
        CPUARMState env={0};
        env.cpu.apple_modern_guarded=modern;
        env.modern_gl=modern_gl; env.legacy_gl=legacy_gl;
        env.hcr=e2h ? HCR_E2H : 0;
        env.reg=(UINT64_C(0x1234)<<48)|UINT64_C(0x40000000);
        uint64_t value=env.reg^UINT64_C(0x1000);
        if (asid_change) value^=UINT64_C(1)<<48;
        uint32_t expected=ARMMMUIdxBit_E20_0;
        if (modern) expected|=ARMMMUIdxBit_E20_2|ARMMMUIdxBit_E20_2_PAN|
                              ARMMMUIdxBit_GE20_2|ARMMMUIdxBit_GE20_2_PAN;
        else if (legacy_gl) expected|=ARMMMUIdxBit_GE20_2|ARMMMUIdxBit_GE20_2_PAN;
        else expected|=ARMMMUIdxBit_E20_2|ARMMMUIdxBit_E20_2_PAN;
        vmsa_tcr_ttbr_el2_write(&env,&ri,value);
        checks++;assert(env.reg==value);
        checks++;assert(env.flush_count==(e2h && asid_change));
        checks++;assert(env.flush_mask==((e2h && asid_change) ? expected : 0));
        checks++;assert(env.legacy_gl==legacy_gl && env.modern_gl==modern_gl);
    }
    printf("%u production ASID flush checks passed (ASan+UBSan)\n",checks);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--negative-oracle', action='store_true')
    args = parser.parse_args()
    source = (args.repo / 'target/arm/helper.c').read_text()
    production = function(source, 'vmsa_tcr_ttbr_el2_write')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    variants = [('production', production)]
    if args.negative_oracle:
        predicate = 'env_archcpu(env)->apple_modern_guarded'
        if production.count(predicate) != 1:
            raise RuntimeError('Missing isolated modern bank predicate')
        variants.append(('legacy-only-oracle', production.replace(predicate,
                           'env_archcpu(env)->apple_modern_guarded && false')))
    with tempfile.TemporaryDirectory(prefix='apple-context-unit-') as directory:
        path = Path(directory) / 'fixture.c'
        binary = Path(directory) / 'fixture'
        for label, callback in variants:
            path.write_text(PRELUDE + callback + TESTS)
            subprocess.run([args.cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fno-omit-frame-pointer', '-fsanitize=address,undefined',
                            str(path), '-o', str(binary)], check=True, timeout=60)
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    env=os.environ, timeout=30)
            if label == 'production':
                print(result.stdout, end='')
                if result.returncode:
                    print(result.stderr, end='')
                    raise SystemExit(result.returncode)
            else:
                if not result.returncode or 'Assertion' not in result.stderr:
                    raise RuntimeError('Legacy-only flush oracle was not rejected')
                print('legacy-only ASID flush oracle rejected by recorded-mask assertion')


if __name__ == '__main__':
    main()
