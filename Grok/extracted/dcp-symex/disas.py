import lief,sys
from capstone import *
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
for p in sys.argv[1:]:
    b=lief.MachO.parse(p).at(0); raw=open(p,'rb').read()
    with open(p+'.s','w') as o:
        for s in b.segments:
            for sec in s.sections:
                if sec.name not in ("__text","__text_exec"): continue
                d=raw[sec.offset:sec.offset+sec.size]; a=sec.virtual_address
                for off in range(0,len(d),4):
                    w=d[off:off+4]; i=next(cs.disasm(w,a+off),None)
                    hx=' '.join(f'{x:02x}' for x in w)
                    o.write(f'{a+off:#x}:  {hx}   {i.mnemonic}\t{i.op_str}\n' if i else f'{a+off:#x}:  {hx}   .word\n')
