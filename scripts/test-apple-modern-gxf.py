#!/usr/bin/env python3
"""Test production modern register tables and shared VHE callbacks.

The fixture replaces QEMU object/table plumbing and effective EL/HCR lookup;
the register definitions, alias installation/accessors, raw access, permission
bit test, reset and configuration validation are actual production source.
This is a register component test, not CPU instruction or firmware execution.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile


def function(source, name):
    match = re.search(r"^[^\n;{}]*\b" + re.escape(name) +
                      r"\([^;{}]*?\)\n\{", source, re.M)
    if match is None:
        raise RuntimeError(f"Missing production function {name}")
    pos = match.end()
    depth = 1
    while depth:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1
    return source[match.start():pos] + "\n"


PRELUDE = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "modern-gxf.h"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define assert_null(p) assert((p) == NULL)
#define QEMU_BUILD_BUG_ON(expr) _Static_assert(!(expr), "build bug")
#define ARM_CP_STATE_AA64 2
#define ARM_CP_SPECIAL_MASK 15
#define ARM_CP_CONST (1 << 4)
#define ARM_CP_64BIT (1 << 5)
#define ARM_CP_ALIAS (1 << 8)
#define ARM_CP_NO_RAW (1 << 10)
#define NV2_REDIR_NV1 0x4000
#define NV2_REDIR_NO_NV1 0x8000
#define CP_REG_AA64_MASK (1U << 28)
#define CP_REG_ARM_COPROC_SHIFT 16
#define CP_REG_ARM64_SYSREG_CP 0x0013
#define CP_REG_ARM64_SYSREG_OP0_MASK 0xc000
#define CP_REG_ARM64_SYSREG_OP0_SHIFT 14
#define CP_REG_ARM64_SYSREG_OP1_MASK 0x3800
#define CP_REG_ARM64_SYSREG_OP1_SHIFT 11
#define CP_REG_ARM64_SYSREG_CRN_MASK 0x0780
#define CP_REG_ARM64_SYSREG_CRN_SHIFT 7
#define CP_REG_ARM64_SYSREG_CRM_MASK 0x0078
#define CP_REG_ARM64_SYSREG_CRM_SHIFT 3
#define CP_REG_ARM64_SYSREG_OP2_MASK 0x0007
#define CP_REG_ARM64_SYSREG_OP2_SHIFT 0
#define ENCODE_AA64_CP_REG(cp, crn, crm, op0, op1, op2) \
    (CP_REG_AA64_MASK | ((cp) << 16) | ((op0) << 14) | \
     ((op1) << 11) | ((crn) << 7) | ((crm) << 3) | (op2))
#define CPREG_FIELD32(env, ri) (*(uint32_t *)((char *)(env) + (ri)->fieldoffset))
#define CPREG_FIELD64(env, ri) (*(uint64_t *)((char *)(env) + (ri)->fieldoffset))
#define HCR_E2H (1ULL << 34)
#define ARM_FEATURE_AARCH64 1
#define ARM_FEATURE_EL2 2
#define ARM_FEATURE_GXF 4
typedef enum {
    PL3_R=0x80, PL3_W=0x40, PL2_R=0xa0, PL2_W=0x50,
    PL1_R=0xa8, PL1_W=0x54, PL3_RW=0xc0, PL2_RW=0xf0, PL1_RW=0xfc
} CPAccessRights;
typedef enum { CP_ACCESS_OK=0, CP_ACCESS_UNDEFINED=8 } CPAccessResult;
typedef struct CPUARMState {
    uint64_t prefix;
    AppleModernGXFState modern_gxf;
    uint64_t features, hcr;
    int current_el;
} CPUARMState;
typedef struct ARMCPRegInfo ARMCPRegInfo;
typedef uint64_t CPReadFn(CPUARMState *, const ARMCPRegInfo *);
typedef void CPWriteFn(CPUARMState *, const ARMCPRegInfo *, uint64_t);
typedef CPAccessResult CPAccessFn(CPUARMState *, const ARMCPRegInfo *, bool);
typedef void CPResetFn(CPUARMState *, const ARMCPRegInfo *);
struct ARMCPRegInfo {
    const char *name;
    unsigned state, type, access, opc0, opc1, opc2, crn, crm;
    ptrdiff_t fieldoffset;
    uint64_t resetvalue;
    uint32_t nv2_redirect_offset;
    void *opaque;
    CPReadFn *readfn, *raw_readfn, *orig_readfn;
    CPWriteFn *writefn, *raw_writefn, *orig_writefn;
    CPAccessFn *accessfn, *orig_accessfn;
    CPResetFn *resetfn;
};
typedef struct Table {
    struct { uint32_t key; ARMCPRegInfo value; } entries[128];
    size_t count;
} Table;
typedef struct ArchCPU {
    CPUARMState env;
    bool apple_modern_gxf, apple_modern_timers, apple_modern_guarded;
    bool has_el2, has_el3, prop_pauth_noop, prop_pauth, vh;
    GPtrArray *modern_vhe_snapshots;
    Table table;
    Table *cp_regs;
} ARMCPU;
typedef struct Error { char message[256]; } Error;
static bool tcg_on = true;
static bool tcg_enabled(void) { return tcg_on; }
static bool arm_feature(CPUARMState *env, uint64_t flag) {
    return (env->features & flag) != 0;
}
#define cpu_isar_feature(name, cpu) ((cpu)->vh)
static void error_setg(Error **errp, const char *fmt, ...) {
    va_list ap;
    assert(errp && !*errp);
    *errp = calloc(1, sizeof(**errp)); assert(*errp);
    va_start(ap, fmt); vsnprintf((*errp)->message, sizeof((*errp)->message), fmt, ap);
    va_end(ap);
}
static int arm_current_el(CPUARMState *env) { return env->current_el; }
static uint64_t arm_hcr_el2_eff(CPUARMState *env) { return env->hcr; }
static ARMCPRegInfo *ARMCPRegTable_get(Table *t, uint32_t key) {
    for (size_t i=0;i<t->count;i++) if (t->entries[i].key==key) return &t->entries[i].value;
    return NULL;
}
static const ARMCPRegInfo *ARMCPRegTable_cget(Table *t, uint32_t key) {
    return ARMCPRegTable_get(t,key);
}
static void ARMCPRegTable_set_at(Table *t, uint32_t key, ARMCPRegInfo value) {
    assert(!ARMCPRegTable_get(t,key)); assert(t->count<ARRAY_SIZE(t->entries));
    t->entries[t->count].key=key; t->entries[t->count++].value=value;
}
static void fixture_register(ARMCPU *cpu, const ARMCPRegInfo *regs, size_t count) {
    for (size_t i=0;i<count;i++) {
        uint32_t key=ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP,regs[i].crn,
            regs[i].crm,regs[i].opc0,regs[i].opc1,regs[i].opc2);
        ARMCPRegTable_set_at(cpu->cp_regs,key,regs[i]);
    }
}
#define define_arm_cp_regs(cpu, regs) fixture_register(cpu,regs,ARRAY_SIZE(regs))
'''

TESTS = r'''
static unsigned checks;
#define CHECK(expr) do { checks++; if (!(expr)) { \
    fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#expr); abort(); } } while (0)
static ARMCPU valid_cpu(void) {
    ARMCPU cpu={0};
    cpu.apple_modern_gxf=true; cpu.has_el2=true; cpu.prop_pauth=true; cpu.vh=true;
    cpu.env.features=ARM_FEATURE_AARCH64|ARM_FEATURE_EL2;
    cpu.env.current_el=2;
    return cpu;
}
static ARMCPRegInfo *named(ARMCPU *cpu, const char *name) {
    for (size_t i=0;i<cpu->table.count;i++)
        if (!strcmp(cpu->table.entries[i].value.name,name)) return &cpu->table.entries[i].value;
    fprintf(stderr,"Missing register %s\n",name); abort();
}
static bool access_ok(ARMCPU *cpu, const ARMCPRegInfo *ri, bool read) {
    if (!cp_access_ok(cpu->env.current_el,ri,read)) return false;
    return !ri->accessfn || ri->accessfn(&cpu->env,ri,read)==CP_ACCESS_OK;
}
static uint64_t read_reg(ARMCPU *cpu,const ARMCPRegInfo *ri) {
    CHECK(access_ok(cpu,ri,true));
    return (ri->readfn ? ri->readfn : raw_read)(&cpu->env,ri);
}
static void write_reg(ARMCPU *cpu,const ARMCPRegInfo *ri,uint64_t value) {
    CHECK(access_ok(cpu,ri,false));
    (ri->writefn ? ri->writefn : raw_write)(&cpu->env,ri,value);
}
static uint64_t raw_value(ARMCPU *cpu,const ARMCPRegInfo *ri) {
    return (ri->raw_readfn ? ri->raw_readfn : raw_read)(&cpu->env,ri);
}
static void reject(ARMCPU *cpu) {
    Error *err=NULL;
    CHECK(!arm_apple_modern_gxf_validate(cpu,&err)); CHECK(err && err->message[0]); free(err);
}
int main(void) {
    ARMCPU cpu=valid_cpu(), changed;
    Error *err=NULL;
    CHECK(arm_apple_modern_gxf_validate(&cpu,&err) && !err);
    changed=cpu; changed.apple_modern_gxf=false; changed.prop_pauth_noop=true;
    changed.env.features|=ARM_FEATURE_GXF;
    CHECK(arm_apple_modern_gxf_validate(&changed,&err) && !err);
    changed=cpu; changed.apple_modern_guarded=true;
    CHECK(arm_apple_modern_gxf_validate(&changed,&err) && !err);
    changed.apple_modern_gxf=false; reject(&changed);
    changed=cpu; changed.prop_pauth_noop=true; reject(&changed);
    changed=cpu; changed.prop_pauth=false; reject(&changed);
    changed=cpu; changed.has_el3=true; reject(&changed);
    changed=cpu; changed.has_el2=false; reject(&changed);
    changed=cpu; changed.vh=false; reject(&changed);
    changed=cpu; changed.env.features|=ARM_FEATURE_GXF; reject(&changed);
    changed=cpu; changed.env.features&=~ARM_FEATURE_AARCH64; reject(&changed);
    changed=cpu; changed.env.features&=~ARM_FEATURE_EL2; reject(&changed);
    tcg_on=false; reject(&cpu); tcg_on=true;
    cpu.cp_regs=&cpu.table;
    arm_register_apple_modern_gxf(&cpu);
    CHECK(cpu.table.count==23);
    arm_register_apple_modern_gxf_aliases(&cpu);
    CHECK(cpu.table.count==32);
    CHECK(cpu.modern_vhe_snapshots && cpu.modern_vhe_snapshots->len==18);
    /* Independently specified modern entry encodings, not table-derived. */
    CHECK(ARMCPRegTable_get(cpu.cp_regs,ENCODE_AA64_CP_REG(0x13,15,8,3,6,1))==named(&cpu,"GXF_ENTRY_EL1"));
    CHECK(ARMCPRegTable_get(cpu.cp_regs,ENCODE_AA64_CP_REG(0x13,15,12,3,6,0))==named(&cpu,"GXF_ENTRY_EL2"));
    CHECK(ARMCPRegTable_get(cpu.cp_regs,ENCODE_AA64_CP_REG(0x13,15,15,3,6,2))==named(&cpu,"GXF_ENTRY_EL12"));
    const char *triads[][3]={
        {"GXF_CONFIG_EL1","GXF_CONFIG_EL2","GXF_CONFIG_EL12"},
        {"GXF_ENTRY_EL1","GXF_ENTRY_EL2","GXF_ENTRY_EL12"},
        {"GXF_PABENTRY_EL1","GXF_PABENTRY_EL2","GXF_PABENTRY_EL12"},
        {"VBAR_GL1","VBAR_GL2","VBAR_GL12"},
        {"SPSR_GL1","SPSR_GL2","SPSR_GL12"},
        {"ASPSR_GL1","ASPSR_GL2","ASPSR_GL12"},
        {"ESR_GL1","ESR_GL2","ESR_GL12"},
        {"ELR_GL1","ELR_GL2","ELR_GL12"},
        {"FAR_GL1","FAR_GL2","FAR_GL12"},
    };
    for (size_t i=0;i<ARRAY_SIZE(triads);i++) {
        ARMCPRegInfo *p1=named(&cpu,triads[i][0]),*p2=named(&cpu,triads[i][1]),*p12=named(&cpu,triads[i][2]);
        CHECK(p12->opaque != p1 && p1->opaque != p2);
        cpu.env.current_el=1; cpu.env.hcr=0;
        write_reg(&cpu,p1,0x11110000+i);
        CHECK(!access_ok(&cpu,p2,true) && !access_ok(&cpu,p2,false));
        CHECK(!access_ok(&cpu,p12,true) && !access_ok(&cpu,p12,false));
        cpu.env.current_el=2;
        write_reg(&cpu,p2,0x22220000+i);
        CHECK(read_reg(&cpu,p1)==0x11110000+i);
        CHECK(read_reg(&cpu,p2)==0x22220000+i);
        CHECK(p12->accessfn(&cpu.env,p12,true)==CP_ACCESS_UNDEFINED);
        CHECK(!access_ok(&cpu,p12,true));
        cpu.env.hcr=HCR_E2H;
        CHECK(read_reg(&cpu,p1)==0x22220000+i);
        write_reg(&cpu,p1,0x33330000+i);
        CHECK(raw_value(&cpu,p2)==0x33330000+i);
        CHECK(raw_value(&cpu,p1)==0x11110000+i);
        CHECK(read_reg(&cpu,p12)==0x11110000+i);
        write_reg(&cpu,p12,0x44440000+i);
        CHECK(raw_value(&cpu,p1)==0x44440000+i);
        CHECK(raw_value(&cpu,p2)==0x33330000+i);
        /* Raw migration/reset access must not take the E2H redirected bank. */
        p1->raw_writefn(&cpu.env,p1,0x55550000+i);
        CHECK(raw_value(&cpu,p1)==0x55550000+i);
        CHECK(raw_value(&cpu,p2)==0x33330000+i);
        cpu.env.current_el=1;
        CHECK(read_reg(&cpu,p1)==0x55550000+i);
    }
    /* SP/TPIDR have independent banks without invented GL12 encodings. */
    const char *pairs[][2]={{"SP_GL1","SP_GL2"},{"TPIDR_GL1","TPIDR_GL2"}};
    cpu.env.current_el=2; cpu.env.hcr=0;
    for(size_t i=0;i<ARRAY_SIZE(pairs);i++) {
        write_reg(&cpu,named(&cpu,pairs[i][0]),10+i);
        write_reg(&cpu,named(&cpu,pairs[i][1]),20+i);
        CHECK(raw_value(&cpu,named(&cpu,pairs[i][0]))==10+i);
        CHECK(raw_value(&cpu,named(&cpu,pairs[i][1]))==20+i);
    }
    ARMCPRegInfo *current=named(&cpu,"CURRENTG");
    CHECK(!access_ok(&cpu,current,false));
    raw_write(&cpu.env,current,1);
    CHECK(read_reg(&cpu,current)==1);
    cpu.env.current_el=1;
    CHECK(read_reg(&cpu,current)==1 && !access_ok(&cpu,current,false));
    cpu.env.current_el=0;
    CHECK(!access_ok(&cpu,current,true));
    /* Exercise production reset over base and alias entries. */
    for(size_t i=0;i<cpu.table.count;i++) cp_reg_reset(&cpu.table.entries[i].value,&cpu);
    AppleModernGXFState zero={0};
    CHECK(!memcmp(&cpu.env.modern_gxf,&zero,sizeof(zero)));
    for(size_t i=0;i<cpu.table.count;i++) CHECK(raw_value(&cpu,&cpu.table.entries[i].value)==0);
    g_clear_pointer(&cpu.modern_vhe_snapshots, g_ptr_array_unref);
    CHECK(cpu.modern_vhe_snapshots == NULL);
    printf("modern GXF register checks passed: %u (no instructions/firmware executed)\n",checks);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--negative-oracle", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    helper = (repo / "target/arm/helper.c").read_text()
    cpu = (repo / "target/arm/cpu.c").read_text()
    cpregs = (repo / "target/arm/cpregs.h").read_text()
    modern = re.sub(r'^#include .*\n', '',
                    (repo / "target/arm/modern-gxf.c").read_text(), flags=re.M)
    functions = "\n".join(function(source, name) for source, name in [
        (cpregs, "cpreg_field_is_64bit"), (cpregs, "cp_access_ok"),
        (helper, "raw_read"), (helper, "raw_write"),
        (helper, "redirect_for_e2h"), (helper, "el2_e2h_read"),
        (helper, "el2_e2h_write"), (helper, "el2_e2h_e12_read"),
        (helper, "el2_e2h_e12_write"), (helper, "el2_e2h_e12_access"),
        (helper, "arm_define_vhe_alias"), (cpu, "cp_reg_reset"),
    ])
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    with tempfile.TemporaryDirectory(prefix="inferno-modern-gxf-") as scratch:
        path = Path(scratch)
        source = path / "registers.c"
        binary = path / "registers"
        variants = [("production", functions)]
        if args.negative_oracle:
            old = "return arm_current_el(env) == 2 && (arm_hcr_el2_eff(env) & HCR_E2H);"
            assert functions.count(old) == 1
            # Suppress E2H through the same lookup expression, keeping functions used.
            variants.append(("broken-E2H-oracle", functions.replace(old,
                "return arm_current_el(env) == 2 && (arm_hcr_el2_eff(env) & 0);")))
        for label, shared in variants:
            source.write_text(PRELUDE + shared + modern + TESTS)
            glib_flags = subprocess.check_output(
                ["pkg-config", "--cflags", "--libs", "glib-2.0"], text=True).split()
            subprocess.run([args.cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                            "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            "-I", str(repo / "target/arm"), str(source), "-o", str(binary),
                            *glib_flags],
                           check=True)
            run = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
            if label == "production":
                print(run.stdout, end="")
                if run.returncode:
                    print(run.stderr, end="")
                    raise SystemExit(run.returncode)
            else:
                if not run.returncode or "FAIL" not in run.stderr:
                    raise RuntimeError("Broken E2H oracle was not rejected by semantic assertions")
                print("broken E2H negative oracle rejected:", run.stderr.strip())


if __name__ == "__main__":
    main()
