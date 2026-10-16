import lief,re,json,sys
KX='/workspace/ios27-re/24A437__iPhone17,3/kx/'
class K:
    def __init__(s,k):
        b=lief.MachO.parse(KX+k).at(0); raw=open(KX+k,'rb').read()
        s.cstr={}
        for seg in b.segments:
            for sec in seg.sections:
                if sec.name in('__cstring','__os_log'):
                    d=raw[sec.offset:sec.offset+sec.size]; a=sec.virtual_address; i=0
                    for part in d.split(b'\0'):
                        if part: s.cstr[a+i]=part.decode('latin1')
                        i+=len(part)+1
        s.L=[];s.idx={}
        for l in open(KX+k+'.s'):
            m=re.match(r'(0x[0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)',l)
            if m: s.idx[int(m[1],16)]=len(s.L); s.L.append((int(m[1],16),m[2],m[3].strip()))
    def func(s,a,maxn=400):
        i=s.idx[a]; out=[]
        for j in range(i,min(len(s.L),i+maxn)):
            if j>i and s.L[j][1]=='bti' and s.L[j][2]=='c': break
            out.append(s.L[j])
        return out
    def strs(s,a,depth=1,seen=None):
        seen=seen or set(); 
        if a in seen or a not in s.idx: return []
        seen.add(a); regs={}; res=[]; calls=[]
        for ad,op,args in s.func(a):
            if op=='adrp': r,v=[x.strip() for x in args.split(',')]; regs[r]=int(v.lstrip('#'),16)
            elif op=='add':
                p=[x.strip() for x in args.split(',')]
                if len(p)==3 and p[1] in regs and p[2].startswith('#'):
                    v=regs[p[1]]+int(p[2].lstrip('#'),16)
                    if v in s.cstr: res.append(s.cstr[v])
            elif op=='bl':
                try: calls.append(int(args,16))
                except: pass
        if depth>0:
            for c in calls[:6]: res+= [x for x in s.strs(c,depth-1,seen) if x not in res]
        return res
