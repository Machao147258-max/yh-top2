# -*- coding: utf-8 -*-
"""列所有 dex 里 com/netease/* 的类及其方法/字段。"""
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    a,d,dx=AnalyzeDex(os.path.join(D,fn))
    for c in d.get_classes():
        n=c.get_name()
        if "netease" in n or "sdkwrapper" in n:
            fs=[(f.get_name(),f.get_descriptor() if hasattr(f,'get_descriptor') else '') for f in c.get_fields()]
            ms=[m.get_name() for m in c.get_methods()]
            print(f"[{fn[:9]}] {n}")
            print(f"    字段({len(fs)}): {fs[:20]}")
            print(f"    方法({len(ms)}): {ms}")
