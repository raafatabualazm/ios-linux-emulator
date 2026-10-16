import sys,json,re,struct; sys.path.insert(0,'/workspace/dcp-symex'); from strrefs import K
refs=json.load(open('tag_refs.json')); out={}
ks={}
for t,rs in sorted(refs.items()):
    if t[0]!='A': continue
    for r in rs:
        if 'addr' not in r: continue
        kname=[k for k in ['com.apple.driver.AppleMobileDispH17P-DCP','com.apple.iokit.IOMobileGraphicsFamily-DCP'] if k.startswith(r['file'])][0]
        k=ks.setdefault(kname,K(kname)); a=int(r['addr'],16); i=k.idx[a]
        st={}
        # backward window then forward to call
        win=k.L[max(0,i-20):i+25]; call=None
        for ad,op,args in win:
            m=re.match(r'([wx][2-5]), (?:#(0x[0-9a-f]+|\d+)|([wx]zr))$',args)
            if op in('mov','movz') and m: st[m[1][1]]= int(m[2],0) if m[2] else 0
            if ad>a and op in('bl','blraa','blr','b'):
                call=(op,args); break
        # find enclosing function
        j=i
        while j>0 and not (k.L[j][1]=='bti' and k.L[j][2]=='c'): j-=1
        fn=k.L[j][0]
        names=[s for s in k.strs(fn,0) if ('::' in s and '(' in s)][:2]
        e=out.setdefault(t,[])
        e.append(dict(kext=kname.split('.')[-1],site=hex(a),func=hex(fn),in_len=st.get('3'),out_len=st.get('5'),call=call,names=names))
json.dump(out,open('a_calls.json','w'),indent=1)
for t,v in out.items():
    for e in v: print(t,e['kext'][:12],e['in_len'],e['out_len'],e['call'],' | '.join(n[:80] for n in e['names']))
