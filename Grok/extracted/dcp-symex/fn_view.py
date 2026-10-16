import sys,json,re; sys.path.insert(0,'/workspace/dcp-symex'); from strrefs import K
a=json.load(open('a_calls.json')); stub={}
for t,v in a.items():
    for e in v: stub[int(e['func'],16)]=t
kname=sys.argv[1]; k=K(kname); addr=int(sys.argv[2],16)
j=k.idx[addr]
while not (k.L[j][1]=='bti' and k.L[j][2]=='c'): j-=1
fn=k.L[j][0]; print('func',hex(fn))
regs={}
for ad,op,args in k.func(fn,3000):
    note=''
    if op=='adrp': r,v=[x.strip() for x in args.split(',')]; regs[r]=int(v.lstrip('#'),16)
    elif op=='add':
        p=[x.strip() for x in args.split(',')]
        if len(p)==3 and p[1] in regs and p[2].startswith('#'):
            v=regs[p[1]]+int(p[2].lstrip('#'),16)
            if v in k.cstr: note='  ; "'+k.cstr[v][:90].strip()+'"'
    if op=='bl':
        try:
            t=int(args,16)
            if t in stub: note=f'  ; ==> {stub[t]}'
        except: pass
    if len(sys.argv)>3 and not note and op not in sys.argv[3].split(','): continue
    print(f'{ad:#x} {op} {args}{note}')
