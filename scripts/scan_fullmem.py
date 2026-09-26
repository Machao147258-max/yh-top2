# -*- coding: utf-8 -*-
import struct,json,sys
KNOWN=set()
for row in json.load(open(r"C:\Users\20751\Desktop\异环\scripts\rl_methods.json")):
    if row[4] is not None: KNOWN.add(row[4])
def align4(x): return (x+3)&~3
def scan(b,need_asc=True,thr=40):
    n=len(b); hits=[]
    for o in range(0,n-4):
        count=struct.unpack_from("<I",b,o)[0]
        if not (60<=count<=200): continue
        cur=o+4; ids=[]; ok=True; prev=-1
        for i in range(count):
            if cur+12>n: ok=False;break
            hdr=struct.unpack_from("<I",b,cur+4)[0]
            ln=struct.unpack_from("<I",b,cur+8)[0]
            idx=hdr&0xffffff
            if idx>2000 or ln>0x100000: ok=False;break
            if need_asc and idx<=prev: ok=False;break
            prev=idx; ids.append(idx)
            cur=align4(cur+12)+ln
        if not ok: continue
        inter=len(set(ids)&KNOWN)
        if inter>=thr: hits.append((o,count,inter,ids[:20]))
    return hits
p=sys.argv[1] if len(sys.argv)>1 else r"C:\Users\20751\Desktop\异环\unidbg\secsdk_fullmem.bin"
b=open(p,"rb").read()
print("size",len(b))
for asc in (True,False):
    h=scan(b,asc)
    print(f"[asc={asc}] 命中 {len(h)}")
    for o,cnt,inter,ids in h[:8]:
        print(f"   @0x{o:x} count={cnt} match={inter} ids={ids}")
