# -*- coding: utf-8 -*-
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
CLASSES=["Lcom/tencent/turingcam/oqKCa;","Lcom/tencent/turingface/sdk/mfa/L32b7;","Lcom/tencent/turingface/sdk/mfa/rBDKv;",
         "Lcom/wpsdk/dfga/sdk/utils/a/e;","Lcom/alipay/sdk/m/a0/b;","Lcom/alipay/sdk/m/a0/e;","Lcom/alipay/sdk/m/s/b;",
         "Lcom/hottagames/yhwrapper/a;","Lcom/tencent/bugly/idasc/proguard/ab;"]
files=["classes5.dex","classes4.dex","classes3.dex"]
tab={}
for fn in files:
    a,d,dx=AnalyzeDex(os.path.join(D,fn))
    for c in d.get_classes():
        if c.get_name() in CLASSES:
            tab[c.get_name()]=(fn,[(m.get_name(),m.get_descriptor()) for m in c.get_methods()])
for cn in CLASSES:
    if cn in tab:
        fn,ms=tab[cn]
        print(f"\n{cn}  ({fn})")
        for n,desc in ms: print(f"   {n}{desc}")
    else: print(f"\n{cn}  —— 未找到")
