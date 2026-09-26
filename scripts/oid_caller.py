# -*- coding: utf-8 -*-
"""查谁调 miitmdid InitSdk / MdidSdkHelper, 确认 OAID SDK 真被使用。"""
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
targets=[("Lcom/bun/miitmdid/core/MdidSdkHelper;","InitSdk"),
         ("Lcom/bun/miitmdid/core/MainMdidSdk;","OnInit"),
         ("Lcom/bun/miitmdid/core/MdidSdkHelper;","<init>")]
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    a,d,dx=AnalyzeDex(os.path.join(D,fn))
    for cls,meth in targets:
        for m in dx.find_methods(classname=cls, methodname=meth):
            xf=list(m.get_xref_from())
            print(f"[{fn[:9]}] {cls}->{meth}: {len(xf)} 调用")
            for c,mm,off in xf[:15]:
                em=mm.get_method()
                print(f"    <- {em.get_class_name()}.{em.get_name()}")
