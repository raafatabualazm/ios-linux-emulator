#!/usr/bin/env python3
"""Sanitize production APSTS access, VHE banks, raw-state and reset behavior.

Register definitions/validation/read/reset, shared VHE callbacks, access masks,
raw callbacks and per-register reset come from production source. QEMU object
plumbing and effective EL/HCR/CPU-feature lookups are fixture substitutes. The
dictionary relocates every insertion to test CPU-owned alias metadata lifetime.
Positive readiness is injected only into fixture backend state to distinguish
banks; no production initialization, CPU instructions or firmware are executed.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "modern_gxf_fixture", Path(__file__).with_name("test-apple-modern-gxf.py"))
GXF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GXF)


def prelude():
    source = GXF.PRELUDE.replace('#include "modern-gxf.h"',
                                '#include "modern-gxf.h"\n#include "modern-apsts.h"')
    source = source.replace("AppleModernGXFState modern_gxf;", """
    AppleModernGXFState modern_gxf;
    AppleModernAPSTSState modern_apsts;
    uint64_t legacy_apctl, legacy_keys[4];""")
    source = source.replace("bool apple_modern_gxf, apple_modern_timers, apple_modern_guarded;",
                            "bool apple_modern_gxf, apple_modern_timers, apple_modern_guarded;\n"
                            "    bool apple_modern_apsts, pauth;")
    source = source.replace("struct { uint32_t key; ARMCPRegInfo value; } entries[128];",
                            "struct Entry { uint32_t key; ARMCPRegInfo value; } *entries;")
    source = source.replace("#define cpu_isar_feature(name, cpu) ((cpu)->vh)", """
#define cpu_isar_feature(name, cpu) fixture_feature_##name(cpu)
static bool fixture_feature_aa64_vh(ARMCPU *cpu) { return cpu->vh; }
static bool fixture_feature_aa64_pauth(ARMCPU *cpu) { return cpu->pauth; }
""")
    start = source.index("static void ARMCPRegTable_set_at")
    old = source[start:source.index("\n}", start) + 2]
    source = source.replace(old, r'''
static void ARMCPRegTable_set_at(Table *t, uint32_t key, ARMCPRegInfo value) {
    assert(!ARMCPRegTable_get(t,key));
    struct Entry *moved=malloc((t->count+1)*sizeof(*moved));
    assert(moved);
    if (t->count) memcpy(moved,t->entries,t->count*sizeof(*moved));
    free(t->entries);
    t->entries=moved;
    t->entries[t->count].key=key; t->entries[t->count++].value=value;
}''')
    source += "\nbool arm_apple_modern_gxf_validate(ARMCPU *, Error **);\n"
    return source


TESTS = r'''
static unsigned checks;
#define CHECK(expr) do { checks++; if (!(expr)) { \
    fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#expr); abort(); } } while (0)
static ARMCPRegInfo *named(ARMCPU *cpu,const char *name) {
    for (size_t i=0;i<cpu->table.count;i++)
        if (!strcmp(cpu->table.entries[i].value.name,name))
            return &cpu->table.entries[i].value;
    fprintf(stderr,"Missing register %s\n",name); abort();
}
static bool access_ok(ARMCPU *cpu,const ARMCPRegInfo *ri,bool read) {
    if (!cp_access_ok(cpu->env.current_el,ri,read)) return false;
    return !ri->accessfn || ri->accessfn(&cpu->env,ri,read)==CP_ACCESS_OK;
}
static uint64_t read_reg(ARMCPU *cpu,const ARMCPRegInfo *ri) {
    CHECK(access_ok(cpu,ri,true));
    return ri->readfn(&cpu->env,ri);
}
static bool guest_write(ARMCPU *cpu,const ARMCPRegInfo *ri,uint64_t value) {
    if (!access_ok(cpu,ri,false)) return false;
    ri->writefn(&cpu->env,ri,value);
    return true;
}
static void initialize(ARMCPU *cpu,uint64_t seed) {
    memset(cpu,0,sizeof(*cpu));
    cpu->apple_modern_apsts=true; cpu->apple_modern_gxf=true;
    cpu->apple_modern_guarded=true; cpu->has_el2=true;
    cpu->prop_pauth=true; cpu->pauth=true; cpu->vh=true;
    cpu->env.features=ARM_FEATURE_AARCH64|ARM_FEATURE_EL2;
    cpu->env.current_el=2; cpu->env.prefix=seed;
    cpu->env.legacy_apctl=seed ^ UINT64_C(0xaaaaaaaa55555555);
    for (unsigned i=0;i<4;i++) cpu->env.legacy_keys[i]=seed ^ i;
    memset(&cpu->env.modern_gxf,0x95,sizeof(cpu->env.modern_gxf));
    cpu->env.modern_apsts.ready_el[0]=true; /* Unexposed slot canary. */
    cpu->cp_regs=&cpu->table;
    Error *err=NULL;
    CHECK(arm_apple_modern_apsts_validate(cpu,&err) && !err);
    arm_register_apple_modern_apsts(cpu);
    CHECK(cpu->table.count==2);
    CHECK(!cpu->env.modern_apsts.ready_el[1]);
    CHECK(!cpu->env.modern_apsts.ready_el[2]);
    arm_register_apple_modern_apsts_aliases(cpu);
    CHECK(cpu->table.count==3);
    CHECK(cpu->modern_vhe_snapshots && cpu->modern_vhe_snapshots->len==2);
    ARMCPRegInfo unrelated={.name="fixture-unrelated"};
    ARMCPRegTable_set_at(cpu->cp_regs,UINT32_MAX,unrelated);
    CHECK(cpu->table.count==4);
}
static void unchanged(ARMCPU *cpu,uint64_t seed) {
    CHECK(cpu->env.prefix==seed);
    CHECK(cpu->env.legacy_apctl==(seed ^ UINT64_C(0xaaaaaaaa55555555)));
    for (unsigned i=0;i<4;i++) CHECK(cpu->env.legacy_keys[i]==(seed ^ i));
    AppleModernGXFState want; memset(&want,0x95,sizeof(want));
    CHECK(!memcmp(&cpu->env.modern_gxf,&want,sizeof(want)));
    CHECK(cpu->env.modern_apsts.ready_el[0]);
}
static void validation(void) {
    /* Independent full configuration truth table, including active PAUTH. */
    for (unsigned flags=0;flags<(1U<<13);flags++) {
        ARMCPU cpu={0}; Error *err=NULL;
        cpu.apple_modern_apsts=(flags & 1)!=0;
        cpu.apple_modern_gxf=(flags & 2)!=0;
        cpu.apple_modern_guarded=(flags & 4)!=0;
        tcg_on=(flags & 8)!=0;
        if (flags & 16) cpu.env.features|=ARM_FEATURE_AARCH64;
        cpu.has_el2=(flags & 32)!=0;
        if (flags & 64) cpu.env.features|=ARM_FEATURE_EL2;
        cpu.has_el3=(flags & 128)!=0;
        cpu.vh=(flags & 256)!=0;
        if (flags & 512) cpu.env.features|=ARM_FEATURE_GXF;
        cpu.prop_pauth=(flags & 1024)!=0;
        cpu.prop_pauth_noop=(flags & 2048)!=0;
        cpu.pauth=(flags & 4096)!=0;
        const unsigned required=2|4|8|16|32|64|256|1024|4096;
        const unsigned forbidden=128|512|2048;
        bool expected=!(flags & 1) ||
            ((flags & required)==required && !(flags & forbidden));
        CHECK(arm_apple_modern_apsts_validate(&cpu,&err)==expected);
        CHECK(expected ? !err : (err && err->message[0]));
        free(err);
    }
    tcg_on=true;
}
static void encodings(ARMCPU *cpu) {
    static const struct { const char *name; unsigned crm,op2,el; bool alias; } want[]={
        {"APSTS_EL1",12,4,1,false}, {"APSTS_EL2",12,3,2,false},
        {"APSTS_EL12",14,7,2,true},
    };
    for (size_t i=0;i<ARRAY_SIZE(want);i++) {
        ARMCPRegInfo *ri=named(cpu,want[i].name);
        CHECK(ARMCPRegTable_get(cpu->cp_regs,
            ENCODE_AA64_CP_REG(0x13,15,want[i].crm,3,6,want[i].op2))==ri);
        CHECK(ri->state==ARM_CP_STATE_AA64);
        CHECK(ri->opc0==3 && ri->opc1==6 && ri->crn==15 &&
              ri->crm==want[i].crm && ri->opc2==want[i].op2);
        CHECK(((ri->type & ARM_CP_ALIAS)!=0)==want[i].alias);
        CHECK(ri->type & ARM_CP_NO_RAW);
        CHECK(ri->fieldoffset==0);
        CHECK(ri->resetvalue==0);
        CHECK(ri->raw_readfn && ri->raw_writefn);
        CHECK(ri->raw_writefn!=raw_write);
        for (unsigned el=0;el<3;el++) {
            cpu->env.current_el=el; cpu->env.hcr=HCR_E2H;
            CHECK(access_ok(cpu,ri,true)==(el>=want[i].el));
            CHECK(!access_ok(cpu,ri,false));
        }
    }
}
static void banks(ARMCPU *cpu) {
    ARMCPRegInfo *p1=named(cpu,"APSTS_EL1"),*p2=named(cpu,"APSTS_EL2"),
                 *p12=named(cpu,"APSTS_EL12");
    CHECK(p1->opaque!=p2 && p12->opaque!=p1);
    for (unsigned ready=0;ready<4;ready++) {
        /* Internal fixture injection only, not a production initialization API. */
        cpu->env.modern_apsts.ready_el[1]=(ready & 1)!=0;
        cpu->env.modern_apsts.ready_el[2]=(ready & 2)!=0;
        for (unsigned el=0;el<3;el++) for (unsigned mode=0;mode<4;mode++) {
            cpu->env.current_el=el;
            cpu->env.hcr=((mode & 1) ? HCR_E2H : 0) |
                        ((mode & 2) ? UINT64_C(1)<<27 : 0); /* TGE. */
            const bool e2h=(mode & 1)!=0;
            if (el>=1) CHECK(read_reg(cpu,p1)==
                (uint64_t)cpu->env.modern_apsts.ready_el[(el==2 && e2h) ? 2 : 1]);
            else CHECK(!access_ok(cpu,p1,true));
            if (el==2) CHECK(read_reg(cpu,p2)==
                (uint64_t)cpu->env.modern_apsts.ready_el[2]);
            else CHECK(!access_ok(cpu,p2,true));
            if (el==2 && e2h) CHECK(read_reg(cpu,p12)==
                (uint64_t)cpu->env.modern_apsts.ready_el[1]);
            else CHECK(!access_ok(cpu,p12,true));
            CHECK(read_raw_cp_reg(&cpu->env,p1)==(uint64_t)((ready & 1)!=0));
            CHECK(read_raw_cp_reg(&cpu->env,p2)==(uint64_t)((ready & 2)!=0));
            CHECK(read_raw_cp_reg(&cpu->env,p12)==(uint64_t)((ready & 1)!=0));
            ARMCPRegInfo *regs[]={p1,p2,p12};
            const uint64_t values[]={0,1,2,UINT64_MAX};
            for (size_t i=0;i<ARRAY_SIZE(regs);i++) {
                for (size_t j=0;j<ARRAY_SIZE(values);j++) {
                    AppleModernAPSTSState before=cpu->env.modern_apsts;
                    CHECK(!guest_write(cpu,regs[i],values[j]));
                    CHECK(!memcmp(&cpu->env.modern_apsts,&before,sizeof(before)));
                    write_raw_cp_reg(&cpu->env,regs[i],values[j]);
                    CHECK(!memcmp(&cpu->env.modern_apsts,&before,sizeof(before)));
                    regs[i]->writefn(&cpu->env,regs[i],values[j]);
                    CHECK(!memcmp(&cpu->env.modern_apsts,&before,sizeof(before)));
                }
            }
        }
    }
    CHECK(apple_modern_apsts_value(&cpu->env.modern_apsts,0)==0);
    CHECK(apple_modern_apsts_value(&cpu->env.modern_apsts,3)==0);
    CHECK(apple_modern_apsts_value(&cpu->env.modern_apsts,UINT32_MAX)==0);
}
static void reset_registers(ARMCPU *cpu) {
    ARMCPRegInfo *p1=named(cpu,"APSTS_EL1"),*p2=named(cpu,"APSTS_EL2"),
                 *p12=named(cpu,"APSTS_EL12");
    cpu->env.current_el=2; cpu->env.hcr=HCR_E2H;
    for (unsigned pass=0;pass<2;pass++) {
        cpu->env.modern_apsts.ready_el[1]=true;
        cpu->env.modern_apsts.ready_el[2]=true;
        cp_reg_reset(p12,cpu);
        CHECK(cpu->env.modern_apsts.ready_el[1] &&
              cpu->env.modern_apsts.ready_el[2]);
        cp_reg_reset(p1,cpu);
        CHECK(!cpu->env.modern_apsts.ready_el[1]);
        CHECK(cpu->env.modern_apsts.ready_el[2]);
        CHECK(read_reg(cpu,p12)==0 && read_reg(cpu,p1)==1);
        cp_reg_reset(p2,cpu);
        CHECK(!cpu->env.modern_apsts.ready_el[2]);
        CHECK(read_reg(cpu,p1)==0 && read_reg(cpu,p2)==0);
        CHECK(read_raw_cp_reg(&cpu->env,p1)==0);
        CHECK(read_raw_cp_reg(&cpu->env,p2)==0);
        CHECK(cpu->env.hcr==HCR_E2H && cpu->env.current_el==2);
    }
}
int main(void) {
    validation();
    ARMCPU cpu,other;
    const uint64_t first=UINT64_C(0x123456789abcdef0),
                   second=UINT64_C(0xfedcba9876543210);
    initialize(&cpu,first); initialize(&other,second);
    encodings(&cpu); encodings(&other);
    AppleModernAPSTSState saved=other.env.modern_apsts;
    banks(&cpu);
    CHECK(!memcmp(&other.env.modern_apsts,&saved,sizeof(saved)));
    saved=cpu.env.modern_apsts;
    banks(&other);
    CHECK(!memcmp(&cpu.env.modern_apsts,&saved,sizeof(saved)));
    saved=other.env.modern_apsts;
    reset_registers(&cpu);
    CHECK(!memcmp(&other.env.modern_apsts,&saved,sizeof(saved)));
    reset_registers(&other);
    unchanged(&cpu,first); unchanged(&other,second);
    for (unsigned i=0;i<2;i++) {
        ARMCPU *p=i ? &other : &cpu;
        g_clear_pointer(&p->modern_vhe_snapshots,g_ptr_array_unref);
        CHECK(p->modern_vhe_snapshots==NULL); free(p->table.entries);
    }
    printf("%u modern APSTS production access/VHE/raw/reset/isolation checks passed "
           "(ASan+UBSan; readiness true only in fixture; no CPU/firmware execution)\n",checks);
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
    gxf = (repo / "target/arm/modern-gxf.c").read_text()
    modern = re.sub(r'^#include .*\n', '',
                    (repo / "target/arm/modern-apsts.c").read_text(), flags=re.M)
    shared = "\n".join(GXF.function(source, name) for source, name in [
        (cpregs, "cpreg_field_is_64bit"), (cpregs, "cp_access_ok"),
        (helper, "raw_read"), (helper, "raw_write"),
        (helper, "read_raw_cp_reg"), (helper, "write_raw_cp_reg"),
        (helper, "redirect_for_e2h"), (helper, "el2_e2h_read"),
        (helper, "el2_e2h_write"), (helper, "el2_e2h_e12_read"),
        (helper, "el2_e2h_e12_write"), (helper, "el2_e2h_e12_access"),
        (helper, "arm_define_vhe_alias"), (cpu, "cp_reg_reset"),
        (gxf, "arm_apple_modern_gxf_validate"),
    ])
    variants = [("production", shared, modern)]
    if args.negative_oracle:
        expression = "return arm_current_el(env) == 2 && (arm_hcr_el2_eff(env) & HCR_E2H);"
        assert shared.count(expression) == 1
        variants.append(("wrong-VHE-bank", shared.replace(expression,
                         "return arm_current_el(env) == 2 && (arm_hcr_el2_eff(env) & 0);"), modern))
        expression = 'APSTS_REG("APSTS_EL1", 4, PL1_R)'
        assert modern.count(expression) == 1
        variants.append(("guest-writable", shared,
                         modern.replace(expression, 'APSTS_REG("APSTS_EL1", 4, PL1_RW)')))
        expression = "env->modern_apsts.ready_el[modern_apsts_bank(ri)] = false;"
        assert modern.count(expression) == 1
        variants.append(("incorrect-ready-reset", shared,
                         modern.replace(expression, "env->modern_apsts.ready_el[modern_apsts_bank(ri)] = true;")))
        expression = "state->ready_el[el] ? 1 : 0;"
        assert modern.count(expression) == 1
        variants.append(("reserved-status-bits", shared,
                         modern.replace(expression, "state->ready_el[el] ? 0xff : 0;")))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1"
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "glib-2.0"],
                                    text=True, timeout=30).split()
    with tempfile.TemporaryDirectory(prefix="inferno-modern-apsts-") as scratch:
        path = Path(scratch)
        source, binary = path / "registers.c", path / "registers"
        for label, functions, module in variants:
            source.write_text(prelude() + functions + module + TESTS)
            subprocess.run([args.cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            "-I", str(repo / "target/arm"), str(source), "-o", str(binary),
                            *flags], check=True, timeout=60)
            run = subprocess.run([str(binary)], env=env, capture_output=True, text=True,
                                 timeout=30)
            if label == "production":
                print(run.stdout, end="")
                if run.returncode:
                    print(run.stderr, end="")
                    raise SystemExit(run.returncode)
            else:
                if not run.returncode or "FAIL" not in run.stderr:
                    raise RuntimeError(f"{label} mutation escaped semantic assertions: {run.stderr}")
                print(f"{label} negative oracle rejected: {run.stderr.strip()}")


if __name__ == "__main__":
    main()
