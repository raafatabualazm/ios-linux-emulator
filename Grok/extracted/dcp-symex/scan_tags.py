import re,sys,json,collections,struct
def istag(v):
    b=struct.pack('<I',v)[::-1]  # big-endian chars
    return b[0] in b'AD' and all(0x30<=c<=0x39 for c in b[1:])
def tagstr(v): return struct.pack('>I',v).decode()
out=collections.defaultdict(list)
for f in sys.argv[1:]:
    lines=[]
    for l in open(f):
        m=re.match(r'(0x[0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\w+)\s*(.*)',l)
        if m: lines.append((int(m[1],16),m[2],m[3].strip()))
    func=None
    for i,(a,op,args) in enumerate(lines):
        if op=='pacibsp' or (op=='bti' and i+1<len(lines) and lines[i+1][1]=='pacibsp'): func=a if op=='bti' else func
        if op=='movk' and 'lsl #0x10' in args:
            r=args.split(',')[0]; hi=int(args.split('#')[1].split(',')[0],16)
            lo=None
            for j in range(i-1,max(0,i-8),-1):
                a2,o2,ar2=lines[j]
                if o2 in('mov','movz') and ar2.startswith(r+',') and '#' in ar2:
                    lo=int(ar2.split('#')[1],16)&0xffff;break
            if lo is None: continue
            v=(hi<<16)|lo
            if not istag(v): continue
            # context: next bl and size immediates
            ctx=[];bl=None
            for k in range(i+1,min(len(lines),i+14)):
                a3,o3,ar3=lines[k]
                if o3 in('mov','movz') and re.match(r'w[2-5], #',ar3): ctx.append(ar3)
                if o3 in('bl','blr','blraa','blraaz','b'): bl=(o3,ar3);break
            pre=[lines[j][2] for j in range(max(0,i-10),i) if lines[j][1] in('mov','movz') and re.match(r'w[2-5], #',lines[j][2])]
            out[tagstr(v)].append(dict(file=f.split('/')[-1][:40],addr=hex(a),func=hex(func) if func else None,reg=r,sizes=pre+ctx,call=bl))
# raw data scan
for f in sys.argv[1:]:
    d=open(f[:-2],'rb').read()
    for o in range(0,len(d)-4,4):
        v=struct.unpack_from('<I',d,o)[0]
        if istag(v): out[tagstr(v)].append(dict(file=f.split('/')[-1][:40],dataoff=hex(o)))
json.dump(out,open('/workspace/dcp-symex/tag_refs.json','w'),indent=1)
for t in sorted(out): print(t,len(out[t]),sorted({x['file'][:22] for x in out[t]}))
