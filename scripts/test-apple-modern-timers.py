#!/usr/bin/env python3
"""Sanitize the production Apple timer table, raw stores and CPU validation.

Generic timer callbacks are symbol fixtures here; their runtime behavior is
checked separately by test-apple-modern-timer-qemu.py with actual CPU code.
This component gate checks callback wiring, encodings, independent raw-state
ownership, reset defaults and rejection of unsupported CPU configurations.
"""
import argparse
from pathlib import Path
import re
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
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define ARM_CP_STATE_AA64 2
#define ARM_CP_ALIAS (1 << 8)
#define ARM_CP_IO (1 << 9)
#define ARM_CP_NO_RAW (1 << 10)
#define NV2_REDIR_NV1 0x4000
#define PL0_R 0xaa
#define PL0_RW 0xff
#define PL1_RW 0xfc
#define PL2_RW 0xf0
#define GTIMER_PHYS 0
#define GTIMER_VIRT 1
#define ARM_FEATURE_AARCH64 1
#define ARM_FEATURE_GENERIC_TIMER 2
#define ARM_FEATURE_EL2 4
#define ARM_FEATURE_GXF 8
typedef struct CPUARMState {
    uint64_t prefix;
    struct { struct { uint64_t ctl, cval; } c14_timer[2]; } cp15;
    struct { uint64_t voff_el2, kctl_el1, rdir_el[3]; } apple_modern_timers;
    uint64_t features;
} CPUARMState;
typedef struct ARMCPRegInfo ARMCPRegInfo;
typedef uint64_t CPReadFn(CPUARMState *, const ARMCPRegInfo *);
typedef void CPWriteFn(CPUARMState *, const ARMCPRegInfo *, uint64_t);
typedef int CPAccessFn(CPUARMState *, const ARMCPRegInfo *, bool);
struct ARMCPRegInfo {
    const char *name;
    unsigned state, type, access, opc0, opc1, opc2, crn, crm;
    ptrdiff_t fieldoffset;
    uint64_t resetvalue;
    uint32_t nv2_redirect_offset;
    CPReadFn *readfn, *raw_readfn;
    CPWriteFn *writefn, *raw_writefn;
    CPAccessFn *accessfn;
};
typedef struct ArchCPU {
    CPUARMState env;
    bool apple_modern_timers, has_el2, has_el3, vh;
} ARMCPU;
typedef struct Error { char message[256]; } Error;
static bool tcg_on = true;
static bool tcg_enabled(void) { return tcg_on; }
static bool arm_feature(CPUARMState *env, uint64_t flag) { return (env->features & flag) != 0; }
#define cpu_isar_feature(feature, cpu) ((cpu)->vh)
static bool cpreg_field_is_64bit(const ARMCPRegInfo *ri) { return ri->state == ARM_CP_STATE_AA64; }
#define CPREG_FIELD64(env, ri) (*(uint64_t *)((char *)(env)+(ri)->fieldoffset))
#define CPREG_FIELD32(env, ri) (*(uint32_t *)((char *)(env)+(ri)->fieldoffset))
static void error_setg(Error **errp, const char *format, ...) {
    va_list args;
    assert(errp && !*errp); *errp=calloc(1,sizeof(**errp)); assert(*errp);
    va_start(args,format); vsnprintf((*errp)->message,sizeof((*errp)->message),format,args); va_end(args);
}
'''

TESTS = r'''
static unsigned checks;
#define CHECK(expr) do { checks++; if (!(expr)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#expr); abort(); } } while(0)
static const ARMCPRegInfo *named(const char *name) {
    for (size_t i=0;i<ARRAY_SIZE(apple_modern_timer_cp_reginfo);i++)
        if (!strcmp(apple_modern_timer_cp_reginfo[i].name,name)) return &apple_modern_timer_cp_reginfo[i];
    abort();
}
static void reject(ARMCPU *cpu) {
    Error *err=NULL;
    CHECK(!arm_apple_modern_timers_validate(cpu,&err)); CHECK(err && err->message[0]); free(err);
}
int main(void) {
    ARMCPU cpu={0}, changed;
    Error *err=NULL;
    cpu.apple_modern_timers=true; cpu.has_el2=true; cpu.vh=true;
    cpu.env.features=ARM_FEATURE_AARCH64|ARM_FEATURE_GENERIC_TIMER|ARM_FEATURE_EL2;
    CHECK(arm_apple_modern_timers_validate(&cpu,&err) && !err);
    changed=cpu; changed.apple_modern_timers=false; changed.has_el2=false;
    changed.env.features=ARM_FEATURE_GXF;
    CHECK(arm_apple_modern_timers_validate(&changed,&err) && !err);
    changed=cpu; changed.has_el2=false; reject(&changed);
    changed=cpu; changed.has_el3=true; reject(&changed);
    changed=cpu; changed.vh=false; reject(&changed);
    changed=cpu; changed.env.features^=ARM_FEATURE_AARCH64; reject(&changed);
    changed=cpu; changed.env.features^=ARM_FEATURE_EL2; reject(&changed);
    changed=cpu; changed.env.features^=ARM_FEATURE_GENERIC_TIMER; reject(&changed);
    changed=cpu; changed.env.features|=ARM_FEATURE_GXF; reject(&changed);
    tcg_on=false; reject(&cpu); tcg_on=true;
    CHECK(ARRAY_SIZE(apple_modern_timer_cp_reginfo)==12);
    const struct { const char *name; unsigned op1,crm,op2; } encodings[]={
        {"AGTCNTP_CTL_EL0",1,13,4}, {"AGTCNTV_CTL_EL0",1,0,5},
        {"AGTCNTP_TVAL_EL0",1,11,4}, {"AGTCNTV_TVAL_EL0",1,15,4},
        {"ACNTPCT_EL0",4,10,5}, {"AGTCNTPCT_EL0",4,11,6},
        {"ACNTVCT_EL0",4,10,6}, {"AGTCNTVCT_EL0",4,11,7},
        {"AGTCNTVOFF_EL2",1,9,4}, {"AGTCNTKCTL_EL1",4,9,6},
        {"AGTCNTRDIR_EL1",1,1,5}, {"AGTCNTRDIR_EL2",4,14,5},
    };
    for (size_t i=0;i<ARRAY_SIZE(encodings);i++) {
        const ARMCPRegInfo *ri=named(encodings[i].name);
        CHECK(ri->state==ARM_CP_STATE_AA64 && ri->opc0==3 && ri->crn==15);
        CHECK(ri->opc1==encodings[i].op1 && ri->crm==encodings[i].crm && ri->opc2==encodings[i].op2);
        if (i<8) CHECK(ri->type & ARM_CP_ALIAS);
        else {
            CHECK(!(ri->type & (ARM_CP_ALIAS|ARM_CP_NO_RAW)));
            CHECK(ri->fieldoffset && !ri->readfn && !ri->writefn);
            CHECK(ri->resetvalue==0);
            CHECK(ri->access==(i==8 || i==11 ? PL2_RW : PL1_RW));
            CHECK(raw_read(&cpu.env,ri)==0);
            raw_write(&cpu.env,ri,UINT64_C(0xfedcba9876543210)+i);
            CHECK(raw_read(&cpu.env,ri)==UINT64_C(0xfedcba9876543210)+i);
        }
    }
    for (size_t i=8;i<ARRAY_SIZE(encodings);i++) {
        const ARMCPRegInfo *ri=named(encodings[i].name);
        CHECK(raw_read(&cpu.env,ri)==UINT64_C(0xfedcba9876543210)+i);
        raw_write(&cpu.env,ri,ri->resetvalue);
        CHECK(raw_read(&cpu.env,ri)==0);
    }
    const ARMCPRegInfo *p=named("AGTCNTP_CTL_EL0"),*v=named("AGTCNTV_CTL_EL0");
    CHECK(p->readfn==gt_phys_redir_ctl_read && p->writefn==gt_phys_redir_ctl_write);
    CHECK(v->readfn==gt_virt_redir_ctl_read && v->writefn==gt_virt_redir_ctl_write);
    CHECK(p->accessfn==gt_ptimer_access && v->accessfn==gt_vtimer_access);
    CHECK(p->raw_readfn==raw_read && p->raw_writefn==raw_write);
    CHECK(v->raw_readfn==raw_read && v->raw_writefn==raw_write);
    CHECK(p->fieldoffset==offsetof(CPUARMState,cp15.c14_timer[GTIMER_PHYS].ctl));
    CHECK(v->fieldoffset==offsetof(CPUARMState,cp15.c14_timer[GTIMER_VIRT].ctl));
    CHECK(named("AGTCNTP_TVAL_EL0")->readfn==gt_phys_redir_tval_read);
    CHECK(named("AGTCNTP_TVAL_EL0")->writefn==gt_phys_redir_tval_write);
    CHECK(named("AGTCNTV_TVAL_EL0")->readfn==gt_virt_redir_tval_read);
    CHECK(named("AGTCNTV_TVAL_EL0")->writefn==gt_virt_redir_tval_write);
    const char *physical[]={"ACNTPCT_EL0","AGTCNTPCT_EL0"};
    const char *virtual[]={"ACNTVCT_EL0","AGTCNTVCT_EL0"};
    for (size_t i=0;i<2;i++) {
        p=named(physical[i]); v=named(virtual[i]);
        CHECK(p->readfn==gt_cnt_read && p->accessfn==gt_pct_access);
        CHECK(v->readfn==gt_virt_cnt_read && v->accessfn==gt_vct_access);
        CHECK(p->access==PL0_R && v->access==PL0_R && !p->writefn && !v->writefn);
        CHECK((p->type & ARM_CP_NO_RAW) && (v->type & ARM_CP_NO_RAW));
    }
    printf("%u production timer component checks passed (ASan+UBSan)\n",checks);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    source = (args.repo / 'target/arm/helper.c').read_text()
    table = re.search(r'^static const ARMCPRegInfo apple_modern_timer_cp_reginfo\[\] = \{.*?^\};',
                      source, re.M | re.S)
    if not table:
        raise RuntimeError('Missing production Apple timer table')
    callbacks = ''
    for name in ('gt_phys_redir_ctl_read', 'gt_virt_redir_ctl_read',
                 'gt_phys_redir_tval_read', 'gt_virt_redir_tval_read',
                 'gt_cnt_read', 'gt_virt_cnt_read'):
        callbacks += f'static uint64_t {name}(CPUARMState *env,const ARMCPRegInfo *ri) {{ (void)env;(void)ri;return 0; }}\n'
    for name in ('gt_phys_redir_ctl_write', 'gt_virt_redir_ctl_write',
                 'gt_phys_redir_tval_write', 'gt_virt_redir_tval_write'):
        callbacks += f'static void {name}(CPUARMState *env,const ARMCPRegInfo *ri,uint64_t value) {{ (void)env;(void)ri;(void)value; }}\n'
    for name in ('gt_ptimer_access', 'gt_vtimer_access', 'gt_pct_access', 'gt_vct_access'):
        callbacks += f'static int {name}(CPUARMState *env,const ARMCPRegInfo *ri,bool read) {{ (void)env;(void)ri;(void)read;return 0; }}\n'
    fixture = (PRELUDE + function(source, 'raw_read') + function(source, 'raw_write')
               + callbacks + table[0] + '\n' + function(source, 'arm_apple_modern_timers_validate') + TESTS)
    with tempfile.TemporaryDirectory(prefix='apple-timer-unit-') as directory:
        path = Path(directory) / 'fixture.c'
        binary = Path(directory) / 'fixture'
        path.write_text(fixture)
        subprocess.run([args.cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fno-omit-frame-pointer', '-fsanitize=address,undefined',
                        str(path), '-o', str(binary)], check=True, timeout=60)
        subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == '__main__':
    main()
