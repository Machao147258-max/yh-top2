# -*- coding: utf-8 -*-
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
JOBS=[
 ("classes5.dex","Lcom/tencent/turingcam/oqKCa;","b","(I)Lcom/tencent/turingface/sdk/mfa/bUA8L;",90),
 ("classes5.dex","Lcom/tencent/turingface/sdk/mfa/L32b7;","a","(Landroid/content/Context;)Ljava/lang/String;",90),
]
cache={}
for fn,cn,mn,desc,lim in JOBS:
    if fn not in cache:
        a,d,dx=AnalyzeDex(os.path.join(D,fn)); cache[fn]=d
    d=cache[fn]
    for c in d.get_classes():
        if c.get_name()!=cn: continue
        for m in c.get_methods():
            if m.get_name()==mn and m.get_descriptor()==desc:
                print(f"\n=== {fn} {cn}->{mn}{desc} ===")
                for i,ins in enumerate(m.get_instructions()):
                    if i>lim: print("   ...(截断)"); break
                    print("   ",ins.get_name(),ins.get_output())
