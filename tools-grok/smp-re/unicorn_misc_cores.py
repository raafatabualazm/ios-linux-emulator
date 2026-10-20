"""Unicorn-emulate the RegMap store leaf that configMiscCores reaches.
Hooks MMIO window at a fake base and logs the exact store.
"""
from unicorn import *
from unicorn.arm64_const import *
import sys;sys.path.insert(0,'/workspace/re-20261020/lib')
from kc import KC

k=KC('/workspace/re-20261020/kc.bin')
# Leaf at 0xfffffff0092afaa8: after PAC/auth, does:
#   bl get_regmap_base  -> returns x0 with +0x18 = base
#   str w23, [x8, w20, uxtw]
# Emulate just the store site by crafting registers.

CODE_VA = 0xfffffff0092afab8  # ldr x8,[x0,#0x18]; str w23,[x8,w20,uxtw]
CODE = k.read(CODE_VA, 8)
print('bytes', CODE.hex())

PAGE = 0x1000
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
# map code page (identity of VA page)
code_base = CODE_VA & ~0xfff
mu.mem_map(code_base, PAGE, UC_PROT_ALL)
mu.mem_write(code_base, k.read(code_base, PAGE))

# Fake RegMap descriptor at 0x40000000, +0x18 points to MMIO
DESC = 0x40000000
MMIO = 0x50000000
mu.mem_map(DESC, PAGE, UC_PROT_ALL)
mu.mem_write(DESC + 0x18, (MMIO).to_bytes(8,'little'))
mu.mem_map(MMIO, PAGE, UC_PROT_ALL)
mu.mem_write(MMIO, b'\x00'*PAGE)

writes=[]
def hook_mem(uc, access, address, size, value, user):
    if access == UC_MEM_WRITE:
        writes.append((address, size, value))
        print(f'WRITE @{address:#x} size={size} value={value:#x}')
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem)

# stack
SP = 0x60000000
mu.mem_map(SP-0x10000, 0x20000, UC_PROT_ALL)
mu.reg_write(UC_ARM64_REG_SP, SP)

# x0 = DESC, w20 = offset (+4 for enable), w23 = mask (e.g. 1<<1 for cpu1)
mu.reg_write(UC_ARM64_REG_X0, DESC)
mu.reg_write(UC_ARM64_REG_W20, 4)   # enable offset
mu.reg_write(UC_ARM64_REG_W23, 0x2) # cpu-id 1

# Run two instructions then stop
end = CODE_VA + 8
mu.emu_start(CODE_VA, end)
print('writes', writes)
assert writes == [(MMIO+4, 4, 2)], writes
print('OK: enable write is 32-bit store of mask to MMIO_base+4')
