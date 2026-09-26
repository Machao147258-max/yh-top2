# -*- coding: utf-8 -*-
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
JOBS=[
 ("classes5.dex","Lcom/tencent/turingcam/oqKCa;","b","(Landroid/content/Context;)I",60),
 ("classes5.dex","Lcom/tencent/turingface/sdk/mfa/L32b7;","a","()Z",60),
 ("classes4.dex","Lcom/wpsdk/dfga/sdk/utils/a/e;","b","()Z",60),
 ("classes5.dex","Lcom/alipay/sdk/m/s/b;","e","()Z",60),
 ("classes5.dex","Lcom/alipay/sdk/m/a0/e;","c","()Z",80),
 ("classes5.dex","Lcom/alipay/sdk/m/a0/e;","d","()Z",80),
 ("classes5.dex","Lcom/tencent/bugly/idasc/proguard/ab;","o","()Z",40),
 ("classes5.dex","Lcom/tencent/bugly/idasc/proguard/ab;","p","()Z",40),
]
cache={}
for fn,cn,mn,desc,lim in JOBS:
    if fn not in cache:
        a,d,dx=AnalyzeDex(os.path.join(D,fn)); cache[fn]=d
    d=cache[fn]
    hit=False
    for c in d.get_classes():
        if c.get_name()!=cn: continue
        for m in c.get_methods():
            if m.get_name()==mn and m.get_descriptor()==desc:
                hit=True
                print(f"\n=== {fn} {cn}->{mn}{desc} ===")
                try:
                    for i,ins in enumerate(m.get_instructions()):
                        if i>lim: print("   ...(截断)"); break
                        print("   ",ins.get_name(),ins.get_output())
                except Exception as e: print("  disasm err",e)
    if not hit: print(f"\n=== {cn}->{mn}{desc} 未找到 ===")
