"""Emulate sleh_fiq IPI ack: mrs IPI_SR; msr IPI_SR, #1 (W1C bit0); then bit1 W1C with #2."""
from unicorn import *
from unicorn.arm64_const import *
import sys;sys.path.insert(0,'/workspace/re-20261020/lib')
from kc import KC
k=KC('/workspace/re-20261020/kc.bin')

# Emulate the MRS/MSR sequence at 0xfffffff00ad42d10..0xfffffff00ad42d28
# Unicorn doesn't implement Apple sysregs; hook MRS/MSR via UC_HOOK_INTR or decode manually.
# Instead: single-step with a custom CP15 hook via UC_HOOK_CODE and rewrite.

VA=0xfffffff00ad42d10
CODE=k.read(VA, 0x30)
print('bytes',CODE.hex())

mu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
base=VA&~0xfff
mu.mem_map(base,0x2000,UC_PROT_ALL)
mu.mem_write(base,k.read(base,0x2000))
SP=0x70000000; mu.mem_map(SP-0x10000,0x20000,UC_PROT_ALL)
mu.reg_write(UC_ARM64_REG_SP,SP)

# Fake gFastIPI = 1 at the adrp+ldr target: adrp x8,#0xfffffff00b70c000; ldr w8,[x8,#0x240]
# We rewrite that load site to mov w8,#1 so the path is taken.
# Patch at 0xfffffff00ad42d04..0xfffffff00ad42d08: mov w8,#1; nop
import struct
mov_w8_1 = 0x52800028  # mov w8, #1
nop = 0xd503201f
mu.mem_write(0xfffffff00ad42d04, struct.pack('<II', mov_w8_1, nop))

# Sysreg state
ipi_sr = {'v': 0x3}  # both bits pending

def on_code(uc, address, size, user):
    insn = int.from_bytes(uc.mem_read(address,4),'little')
    # MRS Xt, S3_5_C15_C1_1  = 0xd538f5? encode: MRS = 0xd53xxxxx
    # Encoding of mrs x20, s3_5_c15_c1_1:
    # op0=3, op1=5, CRn=15, CRm=1, op2=1, Rt=20
    # 0xd53  | ... let's just match by address
    if address == 0xfffffff00ad42d10:  # mrs x20, s3_5_c15_c1_1
        uc.reg_write(UC_ARM64_REG_X20, ipi_sr['v'])
        print(f'MRS IPI_SR -> {ipi_sr["v"]:#x}')
        uc.reg_write(UC_ARM64_REG_PC, address+4)
        return
    if address == 0xfffffff00ad42d24:  # msr s3_5_c15_c1_1, x19
        v = uc.reg_read(UC_ARM64_REG_X19)
        old = ipi_sr['v']; ipi_sr['v'] = old & ~v  # W1C
        print(f'MSR IPI_SR W1C write={v:#x}  {old:#x}->{ipi_sr["v"]:#x}')
        uc.reg_write(UC_ARM64_REG_PC, address+4)
        return
    # Skip the bl #0xfffffff00ad42ac4 (telemetry)
    if address == 0xfffffff00ad42d20:
        uc.reg_write(UC_ARM64_REG_PC, address+4)
        return
    if address == 0xfffffff00ad42d30:  # bl handler — stop before
        print('reached handler call; stop')
        uc.emu_stop()
        return

mu.hook_add(UC_HOOK_CODE, on_code)
# Also need to skip the first few that load gFastIPI — already patched
try:
    mu.emu_start(0xfffffff00ad42d04, 0xfffffff00ad42d38)
except UcError as e:
    print('stop',e, 'PC',hex(mu.reg_read(UC_ARM64_REG_PC)))
print('final IPI_SR', hex(ipi_sr['v']))
assert ipi_sr['v'] == 0x2, ipi_sr  # bit0 cleared, bit1 still set
print('OK: bit0 W1C with write-1; bit1 left untouched')
