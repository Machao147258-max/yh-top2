# -*- coding: utf-8 -*-
"""按 SepData 格式静态搜: [u32 count][u32 v1,u32 header(id|flags),u32 len, bytes]... 校验 id 集合。"""
import os,json,struct
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
KNOWN=set()
try:
    for cn,mn,desc,st,mid,salt,al in json.load(open(r"C:\Users\20751\Desktop\异环\scripts\rl_methods.json")):
        if mid is not None: KNOWN.add(mid)
except Exception as e: print("ids load",e)
print("已知 id 数:", len(KNOWN), sorted(KNOWN)[:20])
def align4(x): return (x+3)&~3
def try_parse(b,o):
    if o+4>len(b): return None
    count=struct.unpack_from("<I",b,o)[0]
    if not (50<=count<=400): return None
    cur=o+4; ids=[]
    for i in range(count):
        if cur+12>len(b): return None
        v1=struct.unpack_from("<I",b,cur)[0]
        hdr=struct.unpack_from("<I",b,cur+4)[0]
        ln=struct.unpack_from("<I",b,cur+8)[0]
        ids.append(hdr & 0xffffff)
        cur = align4(cur+12)
        if cur+ln>len(b): return None
        cur += ln
        cur = align4(cur) if False else cur
    inter=len(set(ids)&KNOWN)
    return count, inter, set(ids-KNOWN), cur-o
for fn in sorted(os.listdir(D))+["..\\..\\..\\..\\qwork\\libsecsdk.so"]:
    p=fn if os.path.isabs(fn) else os.path.join(D,fn)
    if not p.endswith((".dex",".so")): continue
    b=open(p,"rb").read()
    hits=[]
    for o in range(0,len(b)-4):
        r=try_parse(b,o)
        if r and r[1]>=30: hits.append((o,)+r)
    print(f"\n=== {os.path.basename(p)}: 命中 {len(hits)} ===")
    for o,cnt,inter,unk,span in hits[:10]:
        print(f"  @0x{o:x} count={cnt} 匹配id={inter} 未知id={len(unk)} span={span}")
        if unk: print("     未知id:", sorted(unk)[:20])
