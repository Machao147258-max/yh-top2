# -*- coding: utf-8 -*-
import os,json,struct
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
KNOWN=set()
for row in json.load(open(r"C:\Users\20751\Desktop\异环\scripts\rl_methods.json")):
    mid=row[4]
    if mid is not None: KNOWN.add(mid)
KS=sorted(KNOWN)
print("已知id:", KS)
def align4(x): return (x+3)&~3
def scan(b, endian):
    n=len(b); hits=[]
    for o in range(0,n-4):
        count=struct.unpack_from(endian+"I",b,o)[0]
        if not (1<=count<=2000): continue
        cur=o+4; ids_v1=[]; ids_h=[]; ok=True
        for i in range(count):
            if cur+12>n: ok=False;break
            v1=struct.unpack_from(endian+"I",b,cur)[0]
            hdr=struct.unpack_from(endian+"I",b,cur+4)[0]
            ln=struct.unpack_from(endian+"I",b,cur+8)[0]
            if ln>0x200000: ok=False;break
            i1=v1; i2=hdr&0xffffff
            if i1>100000 and i2>100000: ok=False;break
            ids_v1.append(i1); ids_h.append(i2)
            cur=align4(cur+12)+ln
        if not ok: continue
        m1=len(set(ids_v1)&KNOWN); m2=len(set(ids_h)&KNOWN)
        if max(m1,m2)>=40:
            hits.append((o,count,m1,m2,set(ids_h)-KNOWN,set(ids_v1)-KNOWN))
    return hits
files=[os.path.join(D,f) for f in ["classes.dex","classes2.dex","classes3.dex","classes4.dex","classes5.dex"]]+[r"D:\qwork\libsecsdk.so"]
for p in files:
    b=open(p,"rb").read()
    for endian,tag in (("<","LE"),(">","BE")):
        h=scan(b,endian)
        if h:
            print(f"\n{p} [{tag}] 命中 {len(h)}")
            for o,cnt,m1,m2,uh,uv in h[:8]:
                print(f"  @0x{o:x} count={cnt} match_v1={m1} match_hdr24={m2}")
                print(f"     hdr未知={sorted(uh)[:15]}  v1未知={sorted(uv)[:15]}")
