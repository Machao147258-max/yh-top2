# -*- coding: utf-8 -*-
import os,json,struct
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
KNOWN=set()
for cn,mn,desc,st,mid,salt,al in json.load(open(r"C:\Users\20751\Desktop\异环\scripts\rl_methods.json")):
    if mid is not None: KNOWN.add(mid)
def align4(x): return (x+3)&~3
def try_parse(b,o,n):
    count=struct.unpack_from("<I",b,o)[0]
    if not (60<=count<=250): return None
    cur=o+4; ids=[]; 
    for i in range(count):
        if cur+12>n: return None
        hdr=struct.unpack_from("<I",b,cur+4)[0]
        ln=struct.unpack_from("<I",b,cur+8)[0]
        idx=hdr & 0xffffff
        if idx>2000 or ln>0x100000: return None
        ids.append(idx)
        cur=align4(cur+12)+ln
    if cur>n: return None
    inter=len(set(ids)&KNOWN)
    return count, inter, set(ids-KNOWN)
files=[os.path.join(D,"classes.dex"), r"D:\qwork\libsecsdk.so"]
for p in files:
    b=open(p,"rb").read(); n=len(b); hits=[]
    for o in range(0,n-4):
        count=struct.unpack_from("<I",b,o)[0]
        if not (60<=count<=250): continue
        r=try_parse(b,o,n)
        if r and r[1]>=40: hits.append((o,)+r)
    print(f"\n{p}: 命中 {len(hits)}")
    for o,cnt,inter,unk in hits[:12]:
        print(f"  @0x{o:x} count={cnt} match={inter} unknown={len(unk)}")
        if unk: print("     unknown:",sorted(unk)[:25])
