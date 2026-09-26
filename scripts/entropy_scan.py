# -*- coding: utf-8 -*-
"""1) 列虚拟化类的全部方法(找可疑合成方法); 2) 对 dex 做 4KB 熵扫描找加密块。"""
import os,math,struct
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"

# 1) 列方法
a,d,dx=AnalyzeDex(os.path.join(D,"classes.dex"))
for cn in ["Lcom/bun/miitmdid/provider/DefaultProvider;","Lcom/bun/miitmdid/content/ContextKeeper;","Lcom/bun/miitmdid/core/MdidSdkHelper;"]:
    for c in d.get_classes():
        if c.get_name()==cn:
            ms=[(m.get_name(),m.get_descriptor(),"static" in str(m.get_access_flags_string())) for m in c.get_methods()]
            print(f"\n{cn}  方法数={len(ms)}")
            for n,desc,st in ms: print(f"   {n}{desc}  {'ST' if st else ''}")

# 2) 熵扫描
def H(b):
    if not b: return 0
    from collections import Counter
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    b=open(os.path.join(D,fn),"rb").read()
    hi=[]
    for off in range(0,len(b)-4096,4096):
        e=H(b[off:off+4096])
        if e>7.5: hi.append((off,e))
    print(f"\n{fn}: 高熵块(>7.5) {len(hi)}")
    for off,e in hi[:15]: print(f"   @0x{off:x} H={e:.2f}")
