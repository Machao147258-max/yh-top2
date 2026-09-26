# -*- coding: utf-8 -*-
"""全 5 dex 扫 invoke -> Utils.rL; 列出所有被虚拟化的方法。"""
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
TGT="Lcom/netease/nis/sdkwrapper/Utils;"
allcallers=[]
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    a,d,dx=AnalyzeDex(os.path.join(D,fn))
    for cls in d.get_classes():
        for m in cls.get_methods():
            code=m.get_code()
            if code is None: continue
            for ins in code.get_bc().get_instructions():
                if ins.get_name().startswith("invoke") and TGT in (ins.get_output() or ""):
                    allcallers.append((fn, m.get_class_name(), m.get_name(), m.get_descriptor()))
                    break
print(f"总计调用 Utils.rL 的方法数: {len(allcallers)}")
from collections import Counter
pkg=Counter(c[1].rsplit("/",1)[0] for c in allcallers)
print("按包:", dict(pkg))
print("\n全部被虚拟化(调rL)的方法:")
for fn,cn,mn,desc in allcallers:
    print(f"  [{fn[:9]}] {cn}->{mn}{desc}")
