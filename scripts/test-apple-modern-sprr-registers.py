#!/usr/bin/env python3
"""Sanitize production modern SPRR register, VHE, flush and reset behavior.

QEMU object plumbing and effective EL/HCR lookup are fixture substitutes.
SPRR definitions/writer/validation, shared VHE callbacks, raw access,
access-right checks and individual-register reset use production source.
The dictionary deliberately relocates entries on every insertion. Permission
table and PTW behavior are covered by their separate fixture; no instructions
or firmware are executed here.
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
                                '#include "modern-gxf.h"\n#include "modern-sprr.h"')
    source = source.replace("PL3_RW=0xc0, PL2_RW=0xf0, PL1_RW=0xfc",
                            "PL3_RW=0xc0, PL2_RW=0xf0, PL1_RW=0xfc, PL0_R=0xaa, "
                            "PL0_RW=0xff")
    source = source.replace("typedef struct CPUARMState {", """
typedef struct CPUState { unsigned flushes; } CPUState;
static CPUState *last_flush;
typedef struct CPUARMState {""")
    source = source.replace("AppleModernGXFState modern_gxf;", """
    AppleModernGXFState modern_gxf;
    AppleModernSPRRState modern_sprr;
    uint64_t legacy_sprr[4][2];
    CPUState *owner;""")
    source = source.replace("struct { uint32_t key; ARMCPRegInfo value; } entries[128];",
                            "struct Entry { uint32_t key; ARMCPRegInfo value; } *entries;")
    source = source.replace("bool apple_modern_gxf, apple_modern_timers, apple_modern_guarded;",
                            "bool apple_modern_gxf, apple_modern_timers, apple_modern_guarded;\n"
                            "    bool apple_modern_sprr;\n    CPUState cpu_state;")
    start = source.index("static void ARMCPRegTable_set_at")
    old = source[start:source.index("\n}", start) + 2]
    source = source.replace(old, r'''
static void ARMCPRegTable_set_at(Table *t, uint32_t key, ARMCPRegInfo value) {
    assert(!ARMCPRegTable_get(t,key));
    struct Entry *moved = malloc((t->count + 1) * sizeof(*moved));
    assert(moved);
    if (t->count) memcpy(moved, t->entries, t->count * sizeof(*moved));
    free(t->entries);
    t->entries = moved;
    t->entries[t->count].key=key; t->entries[t->count++].value=value;
}''')
    source += r'''
#define PAGE_READ 1
#define PAGE_WRITE 2
#define PAGE_EXEC 4
static CPUState *env_cpu(CPUARMState *env) { return env->owner; }
static void tlb_flush(CPUState *cpu) {
    assert(cpu); cpu->flushes++; last_flush = cpu;
}
/* UPERM writes flush only the EL0 regimes (ordinary and guarded EL0). */
#define ARMMMUIdxBit_E10_0 (1u << 0)
#define ARMMMUIdxBit_E20_0 (1u << 1)
static void tlb_flush_by_mmuidx(CPUState *cpu, unsigned idxmap) {
    assert(cpu);
    assert(idxmap == (ARMMMUIdxBit_E10_0 | ARMMMUIdxBit_E20_0));
    cpu->flushes++; last_flush = cpu;
}
'''
    return source


TESTS = r'''
static unsigned checks;
#define CHECK(expr) do { checks++; if (!(expr)) { \
    fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#expr); abort(); } } while (0)
static ARMCPRegInfo *named(ARMCPU *cpu, const char *name) {
    for (size_t i=0;i<cpu->table.count;i++)
        if (!strcmp(cpu->table.entries[i].value.name,name))
            return &cpu->table.entries[i].value;
    fprintf(stderr,"Missing register %s\n",name); abort();
}
static bool access_ok(ARMCPU *cpu, const ARMCPRegInfo *ri, bool read) {
    if (!cp_access_ok(cpu->env.current_el,ri,read)) return false;
    return !ri->accessfn || ri->accessfn(&cpu->env,ri,read)==CP_ACCESS_OK;
}
static uint64_t read_reg(ARMCPU *cpu, const ARMCPRegInfo *ri) {
    CHECK(access_ok(cpu,ri,true));
    return (ri->readfn ? ri->readfn : raw_read)(&cpu->env,ri);
}
static void write_reg(ARMCPU *cpu, const ARMCPRegInfo *ri, uint64_t value) {
    unsigned before=cpu->cpu_state.flushes;
    CHECK(access_ok(cpu,ri,false));
    (ri->writefn ? ri->writefn : raw_write)(&cpu->env,ri,value);
    CHECK(cpu->cpu_state.flushes==before+1);
    CHECK(last_flush==&cpu->cpu_state);
}
static uint64_t raw_value(ARMCPU *cpu, const ARMCPRegInfo *ri) {
    return read_raw_cp_reg(&cpu->env,ri);
}
static void raw_store(ARMCPU *cpu, const ARMCPRegInfo *ri, uint64_t value) {
    unsigned before=cpu->cpu_state.flushes;
    write_raw_cp_reg(&cpu->env,ri,value);
    CHECK(cpu->cpu_state.flushes==before);
    CHECK(raw_value(cpu,ri)==value);
}
static void initialize(ARMCPU *cpu, uint64_t seed) {
    memset(cpu,0,sizeof(*cpu));
    cpu->apple_modern_sprr=true; cpu->apple_modern_gxf=true;
    cpu->apple_modern_guarded=true; cpu->has_el2=true;
    cpu->prop_pauth=true; cpu->vh=true;
    cpu->env.features=ARM_FEATURE_AARCH64|ARM_FEATURE_EL2;
    cpu->env.current_el=2; cpu->env.owner=&cpu->cpu_state;
    cpu->env.prefix=seed;
    memset(&cpu->env.modern_gxf,0x95,sizeof(cpu->env.modern_gxf));
    for (size_t i=0;i<4;i++) for (size_t j=0;j<2;j++)
        cpu->env.legacy_sprr[i][j]=seed ^ (i << 8) ^ j;
    cpu->env.modern_sprr.config_el[0]=seed ^ UINT64_C(0xdeadbeef);
    cpu->env.modern_sprr.pperm_el[0]=seed ^ UINT64_C(0xcafef00d);
    cpu->cp_regs=&cpu->table;
    Error *err=NULL;
    CHECK(arm_apple_modern_gxf_validate(cpu,&err) && !err);
    CHECK(arm_apple_modern_sprr_validate(cpu,&err) && !err);
    arm_register_apple_modern_sprr(cpu);
    CHECK(cpu->table.count==5);
    arm_register_apple_modern_sprr_aliases(cpu);
    CHECK(cpu->table.count==7);
    CHECK(cpu->modern_vhe_snapshots && cpu->modern_vhe_snapshots->len==4);
    /* Force a further dictionary relocation after the aliases exist. */
    ARMCPRegInfo unrelated={.name="fixture-unrelated"};
    ARMCPRegTable_set_at(cpu->cp_regs,UINT32_MAX,unrelated);
    CHECK(cpu->table.count==8);
}
static void unchanged(ARMCPU *cpu, uint64_t seed) {
    CHECK(cpu->env.prefix==seed);
    AppleModernGXFState expected;
    memset(&expected,0x95,sizeof(expected));
    CHECK(!memcmp(&cpu->env.modern_gxf,&expected,sizeof(expected)));
    for (size_t i=0;i<4;i++) for (size_t j=0;j<2;j++)
        CHECK(cpu->env.legacy_sprr[i][j]==(seed ^ (i << 8) ^ j));
    CHECK(cpu->env.modern_sprr.config_el[0]==(seed ^ UINT64_C(0xdeadbeef)));
    CHECK(cpu->env.modern_sprr.pperm_el[0]==(seed ^ UINT64_C(0xcafef00d)));
}
static void validation(void) {
    for (unsigned flags=0;flags<8;flags++) {
        ARMCPU cpu={0}; Error *err=NULL;
        cpu.apple_modern_sprr=(flags & 1)!=0;
        cpu.apple_modern_gxf=(flags & 2)!=0;
        cpu.apple_modern_guarded=(flags & 4)!=0;
        bool accepted=arm_apple_modern_sprr_validate(&cpu,&err);
        bool expected=!cpu.apple_modern_sprr ||
            (cpu.apple_modern_gxf && cpu.apple_modern_guarded);
        CHECK(accepted==expected);
        CHECK(expected ? !err : (err && err->message[0]));
        free(err);
    }
}
static void encodings(ARMCPU *cpu) {
    /* Literal independent encoding oracle from Darwin sysregs.py. */
    static const struct { const char *name; unsigned crm, op2, el; bool alias; } want[]={
        {"SPRR_CONFIG_EL1",1,0,1,false}, {"SPRR_CONFIG_EL2",14,2,2,false},
        {"SPRR_PPERM_EL1",1,6,1,false}, {"SPRR_PPERM_EL2",1,7,2,false},
        {"SPRR_UPERM_EL0",1,5,0,false}, {"SPRR_CONFIG_EL12",15,4,2,true},
        {"SPRR_PPERM_EL12",15,7,2,true},
    };
    for (size_t i=0;i<ARRAY_SIZE(want);i++) {
        const ARMCPRegInfo *ri=named(cpu,want[i].name);
        CHECK(ARMCPRegTable_get(cpu->cp_regs,
            ENCODE_AA64_CP_REG(0x13,15,want[i].crm,3,6,want[i].op2))==ri);
        CHECK(ri->state==ARM_CP_STATE_AA64);
        CHECK(ri->opc0==3 && ri->opc1==6 && ri->crn==15 &&
              ri->crm==want[i].crm && ri->opc2==want[i].op2);
        CHECK(ri->resetvalue==0);
        CHECK(((ri->type & ARM_CP_ALIAS)!=0)==want[i].alias);
        CHECK(ri->fieldoffset!=0);
        CHECK(ri->raw_readfn==raw_read && ri->raw_writefn==raw_write);
        for (unsigned el=0;el<3;el++) {
            cpu->env.current_el=el; cpu->env.hcr=HCR_E2H;
            CHECK(access_ok(cpu,ri,true)==(el>=want[i].el));
            /* Read and write share the minimum level, including UPERM at EL0. */
            CHECK(access_ok(cpu,ri,false)==(el>=want[i].el));
        }
    }
}
static void triads(ARMCPU *cpu) {
    const char *names[][3]={
        {"SPRR_CONFIG_EL1","SPRR_CONFIG_EL2","SPRR_CONFIG_EL12"},
        {"SPRR_PPERM_EL1","SPRR_PPERM_EL2","SPRR_PPERM_EL12"},
    };
    for (size_t i=0;i<ARRAY_SIZE(names);i++) {
        ARMCPRegInfo *p1=named(cpu,names[i][0]),*p2=named(cpu,names[i][1]),
                     *p12=named(cpu,names[i][2]);
        const uint64_t a=UINT64_C(0xfedcba9876543210)+i;
        const uint64_t b=UINT64_C(0x0123456789abcdef)-i;
        const uint64_t c=UINT64_C(0x8000000000000001)+i;
        const uint64_t d=UINT64_C(0xaaaaaaaa55555555)+i;
        CHECK(p12->opaque!=p1 && p1->opaque!=p2);
        cpu->env.current_el=1; cpu->env.hcr=0;
        write_reg(cpu,p1,a);
        CHECK(read_reg(cpu,p1)==a);
        CHECK(!access_ok(cpu,p2,true) && !access_ok(cpu,p2,false));
        CHECK(!access_ok(cpu,p12,true) && !access_ok(cpu,p12,false));
        cpu->env.current_el=2;
        write_reg(cpu,p2,b);
        CHECK(read_reg(cpu,p1)==a && read_reg(cpu,p2)==b);
        CHECK(!access_ok(cpu,p12,true) && !access_ok(cpu,p12,false));
        CHECK(p12->accessfn(&cpu->env,p12,true)==CP_ACCESS_UNDEFINED);
        cpu->env.hcr=HCR_E2H;
        CHECK(read_reg(cpu,p1)==b && read_reg(cpu,p2)==b);
        write_reg(cpu,p1,c);
        CHECK(raw_value(cpu,p1)==a && raw_value(cpu,p2)==c);
        CHECK(read_reg(cpu,p12)==a);
        write_reg(cpu,p12,d);
        CHECK(raw_value(cpu,p1)==d && raw_value(cpu,p2)==c);
        /* Identical guest stores also use the production flush callback. */
        write_reg(cpu,p12,d);
        raw_store(cpu,p1,a);
        CHECK(raw_value(cpu,p2)==c && read_reg(cpu,p1)==c);
        raw_store(cpu,p2,b);
        CHECK(raw_value(cpu,p1)==a && read_reg(cpu,p1)==b);
        cpu->env.current_el=1;
        CHECK(read_reg(cpu,p1)==a); /* E2H applies only at EL2. */
        cpu->env.current_el=0;
        CHECK(!access_ok(cpu,p1,true) && !access_ok(cpu,p1,false));
        CHECK(!access_ok(cpu,p2,true) && !access_ok(cpu,p2,false));
        CHECK(!access_ok(cpu,p12,true) && !access_ok(cpu,p12,false));
    }
}
static void uperm(ARMCPU *cpu) {
    ARMCPRegInfo *ri=named(cpu,"SPRR_UPERM_EL0");
    cpu->env.current_el=1; cpu->env.hcr=0;
    write_reg(cpu,ri,UINT64_C(0x8badf00dfeedcafe));
    cpu->env.current_el=0;
    CHECK(read_reg(cpu,ri)==UINT64_C(0x8badf00dfeedcafe));
    /* EL0 may write UPERM (Darwin's PL0_RW); the mask control is unmodeled. */
    write_reg(cpu,ri,UINT64_C(0x0123456789abcdef));
    CHECK(read_reg(cpu,ri)==UINT64_C(0x0123456789abcdef));
    cpu->env.current_el=2; cpu->env.hcr=HCR_E2H;
    CHECK(read_reg(cpu,ri)==UINT64_C(0x0123456789abcdef));
    write_reg(cpu,ri,UINT64_MAX);
    CHECK(raw_value(cpu,ri)==UINT64_MAX);
    raw_store(cpu,ri,UINT64_C(0x1234567800000000));
    CHECK(read_reg(cpu,ri)==UINT64_C(0x1234567800000000));
}
static void reset_registers(ARMCPU *cpu) {
    static const char *bases[]={"SPRR_CONFIG_EL1","SPRR_CONFIG_EL2",
        "SPRR_PPERM_EL1","SPRR_PPERM_EL2","SPRR_UPERM_EL0"};
    cpu->env.current_el=2; cpu->env.hcr=HCR_E2H;
    for (size_t i=0;i<ARRAY_SIZE(bases);i++)
        raw_store(cpu,named(cpu,bases[i]),UINT64_C(0xfedcba9800000000)+i);
    AppleModernSPRRState poisoned=cpu->env.modern_sprr;
    unsigned flushes=cpu->cpu_state.flushes;
    cp_reg_reset(named(cpu,"SPRR_CONFIG_EL12"),cpu);
    cp_reg_reset(named(cpu,"SPRR_PPERM_EL12"),cpu);
    CHECK(!memcmp(&cpu->env.modern_sprr,&poisoned,sizeof(poisoned)));
    for (size_t pass=0;pass<2;pass++) {
        for (size_t i=0;i<ARRAY_SIZE(bases);i++) cp_reg_reset(named(cpu,bases[i]),cpu);
        for (size_t i=0;i<ARRAY_SIZE(bases);i++) CHECK(raw_value(cpu,named(cpu,bases[i]))==0);
        CHECK(raw_value(cpu,named(cpu,"SPRR_CONFIG_EL12"))==0);
        CHECK(raw_value(cpu,named(cpu,"SPRR_PPERM_EL12"))==0);
        CHECK(cpu->cpu_state.flushes==flushes);
        CHECK(cpu->env.hcr==HCR_E2H);
    }
}
int main(void) {
    validation();
    ARMCPU cpu,other;
    const uint64_t seed=UINT64_C(0xffeeddccbbaa0099),second=UINT64_C(0x1122334455667788);
    initialize(&cpu,seed); initialize(&other,second);
    AppleModernSPRRState other_initial=other.env.modern_sprr;
    encodings(&cpu); triads(&cpu); uperm(&cpu);
    unchanged(&cpu,seed); unchanged(&other,second);
    CHECK(other.cpu_state.flushes==0);
    CHECK(!memcmp(&other.env.modern_sprr,&other_initial,sizeof(other_initial)));
    AppleModernSPRRState first=cpu.env.modern_sprr;
    unsigned first_flushes=cpu.cpu_state.flushes;
    encodings(&other); triads(&other); uperm(&other);
    CHECK(cpu.cpu_state.flushes==first_flushes);
    CHECK(!memcmp(&cpu.env.modern_sprr,&first,sizeof(first)));
    AppleModernSPRRState other_tested=other.env.modern_sprr;
    reset_registers(&cpu);
    CHECK(other.cpu_state.flushes==first_flushes);
    CHECK(!memcmp(&other.env.modern_sprr,&other_tested,sizeof(other_tested)));
    reset_registers(&other);
    unchanged(&cpu,seed); unchanged(&other,second);
    for (size_t i=0;i<2;i++) {
        ARMCPU *p=i ? &other : &cpu;
        g_clear_pointer(&p->modern_vhe_snapshots,g_ptr_array_unref);
        CHECK(p->modern_vhe_snapshots==NULL);
        free(p->table.entries);
    }
    printf("%u modern SPRR production register/VHE/access/flush/reset/isolation checks passed (ASan+UBSan; no firmware)\n",checks);
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
                    (repo / "target/arm/modern-sprr.c").read_text(), flags=re.M)
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
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1"
    variants = [("production", shared, modern)]
    if args.negative_oracle:
        expression = "return arm_current_el(env) == 2 && (arm_hcr_el2_eff(env) & HCR_E2H);"
        assert shared.count(expression) == 1
        variants.append(("broken-E2H", shared.replace(expression,
            "return arm_current_el(env) == 2 && (arm_hcr_el2_eff(env) & 0);"), modern))
        assert modern.count("tlb_flush(env_cpu(env));") == 1
        variants.append(("missing-flush", shared, modern.replace("tlb_flush(env_cpu(env));",
            "if (value == UINT64_C(0x3141592653589793)) { tlb_flush(env_cpu(env)); }")))
        uperm_flush = "tlb_flush_by_mmuidx(env_cpu(env),"
        assert modern.count(uperm_flush) == 1
        variants.append(("missing-uperm-flush", shared, modern.replace(uperm_flush,
            "if (value == UINT64_C(0x3141592653589793)) tlb_flush_by_mmuidx(env_cpu(env),")))
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "glib-2.0"],
                                    text=True, timeout=30).split()
    with tempfile.TemporaryDirectory(prefix="inferno-modern-sprr-registers-") as scratch:
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
