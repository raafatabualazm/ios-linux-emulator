import json,re,bisect
KX='/workspace/ios27-re/24A437__iPhone17,3/kx/'
d=json.load(open('d_handlers.json'))
B=0xfffffff007004000
for i,lo in enumerate([0x021d8cc4,0x021d8d18,0x021d8d6c,0x021d8d94,0x021d8e78,0x021d8f48,0x021d9018,0x021d911c]):
    d[f'D00{i}']=dict(kext='com.apple.driver.AppleMobileDispH17P-DCP',lookup='0xfffffff0091dcc94',handler=hex(B+lo))
for i,lo in enumerate([0x03169508,0x03169644,0x03169790,0x031698b0,0x031699d0]):
    d[f'D45{i}']=dict(kext='com.apple.iokit.IOMobileGraphicsFamily-DCP',lookup='0xfffffff00a16d4d8',handler=hex(B+lo))
cache={}
def lines(k):
    if k not in cache:
        L=[];idx={}
        for l in open(KX+k+'.s'):
            m=re.match(r'(0x[0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)',l)
            if m: idx[int(m[1],16)]=len(L); L.append((int(m[1],16),m[2],m[3].strip()))
        cache[k]=(L,idx)
    return cache[k]
for t,v in sorted(d.items()):
    L,idx=lines(v['kext']); h=int(v['handler'],16); i=idx.get(h)
    chk=[];calls=[];ret=None
    if i is None: v['note']='handler not found'; continue
    regs={}
    for a,op,args in L[i:i+60]:
        m=re.match(r'(w[2-5]), #(0x[0-9a-f]+|\d+)$',args)
        if op=='cmp' and m: chk.append(f'{ {"w2":"w2","w3":"in_len","w4":"w4","w5":"out_len"}[m[1]]}>={m[2]}?')
        if op in('bl','b') and not args.startswith('.') and len(calls)<3: calls.append(args)
        if op in('ret','retab') : break
    v['size_checks']=chk; v['calls']=calls
json.dump(d,open('d_handlers.json','w'),indent=1)
for t,v in sorted(d.items()): print(t,v['handler'],v.get('size_checks'),v.get('calls'))
