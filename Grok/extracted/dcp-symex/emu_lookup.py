# Concretely execute DCP->AP callback lookup functions (tag->handler) for every D000..D999.
import lief,struct,json,sys
from unicorn import *; from unicorn.arm64_const import *
from capstone import *
KX='/workspace/ios27-re/24A437__iPhone17,3/kx/'
LOOKUPS={'com.apple.driver.AppleMobileDispH17P-DCP':[0xfffffff0091dcc94,0xfffffff0091dfa7c,0xfffffff0091e5008,0xfffffff0091fc978,0xfffffff0091ffc38],
 'com.apple.iokit.IOMobileGraphicsFamily-DCP':[0xfffffff00a14c0b4,0xfffffff00a16a928,0xfffffff00a16d4d8,0xfffffff00a17125c]}
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
res={}
for kext,fns in LOOKUPS.items():
    b=lief.MachO.parse(KX+kext).at(0); raw=open(KX+kext,'rb').read()
    for fn in fns:
        mu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for s in b.segments:
            if s.virtual_size==0: continue
            base=s.virtual_address&~0xfff; size=((s.virtual_address+s.virtual_size+0xfff)&~0xfff)-base
            try: mu.mem_map(base,size)
            except Exception: pass
            mu.mem_write(s.virtual_address,raw[s.file_offset:s.file_offset+s.file_size])
        mu.mem_map(0x1000,0x10000)
        def hook(mu,addr,size,u):
            ins=bytes(mu.mem_read(addr,4))
            i=next(cs.disasm(ins,addr),None)
            if i and i.mnemonic in('pacia','bti','paciza','xpaci'): mu.reg_write(UC_ARM64_REG_PC,addr+4)
            if i and i.mnemonic in('ret','retab'): mu.emu_stop()
        mu.hook_add(UC_HOOK_CODE,hook)
        for n in range(1000):
            for L in 'D':
                t=f'{L}{n:03d}'; v=struct.unpack('>I',t.encode())[0]
                mu.reg_write(UC_ARM64_REG_X1,v); mu.reg_write(UC_ARM64_REG_X0,0xdead)
                mu.reg_write(UC_ARM64_REG_SP,0x8000); mu.reg_write(UC_ARM64_REG_LR,0x1000)
                try: mu.emu_start(fn,0x1000,count=400)
                except UcError as e: pass
                x0=mu.reg_read(UC_ARM64_REG_X0)
                if x0 not in(0,0xdead) and x0>0xfffffff000000000: res[t]=dict(kext=kext,lookup=hex(fn),handler=hex(x0))
json.dump(res,open('/workspace/dcp-symex/d_handlers.json','w'),indent=1)
print(len(res)); print(' '.join(sorted(res)))
