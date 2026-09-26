# -*- coding: utf-8 -*-
import os,json,struct
KNOWN=set()
for row in json.load(open(r"C:\Users\20751\Desktop\异环\scripts\rl_methods.json")):
    mid=row[4]
    if mid is not None: KNOWN.add(mid)
KL=sorted(KNOWN)
def align4(x): return (x+3)&~3
def scan(b, endian, need_asc=True):
    n=len(b); hits=[]
    for o in range(0,n-4):
        count=struct.unpack_from(endian+"I",b,o)[0]
        if not (60<=count<=200): continue
        cur=o+4; ids=[]; ok=True; prev=-1
        for i in range(count):
            if cur+12>n: ok=False;break
            hdr=struct.unpack_from(endian+"I",b,cur+4)[0]
            ln=struct.unpack_from(endian+"I",b,cur+8)[0]
            idx=hdr&0xffffff
            if idx>2000 or ln>0x100000: ok=False;break
            if need_asc and idx<=prev: ok=False;break
            prev=idx; ids.append(idx)
            cur=align4(cur+12)+ln
        if not ok or cur>n: continue
        inter=len(set(ids)&KNOWN)
        if len(set(ids))>=count*0.9 and inter>=40: hits.append((o,count,inter,ids,cur-o))
    return hits
targets=[r"C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin", r"D:\qwork\libsecsdk.so"]+\
        [r"C:\Users\20751\Desktop\异环\unpacked\dex\classes%d.dex"%i for i in range(1,6)]
for p in targets:
    if not os.path.exists(p): 
        print("缺", p); continue
    b=open(p,"rb").read()
    for endian,tag in (("<","LE"),(">","BE")):
        h=scan(b,endian)
        if h:
            print(f"\n{p} [{tag}] 命中 {len(h)}")
            for o,cnt,inter,ids,span in h[:6]:
                print(f"  @0x{o:x} count={cnt} 命中已知={inter} span={span} id前20={ids[:20]}")
