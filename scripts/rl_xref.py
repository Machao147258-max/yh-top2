# -*- coding: utf-8 -*-
"""用 androguard 正确解析 DEX，找 Utils.rL 的真实调用者(xref)。"""
import os
from androguard.core.dex import DEX
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
TGT="Lcom/netease/nis/sdkwrapper/Utils;"
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    with open(os.path.join(D,fn),"rb") as f: d=DEX(f.read())
    hits=[]
    for m in d.get_methods():
        if m.get_class_name()==TGT:
            for cls,meth,off in m.get_xref_from():
                hits.append((m.get_name(), cls.get_name(), meth.get_name(), off))
    print(f"\n=== {fn}: Utils 方法被调用 xref = {len(hits)} ===")
    for nm,cn,mn,off in hits[:40]:
        print(f"   {nm:16s} <- {cn}.{mn} @0x{off:x}")
    # 目标类是否定义在此dex
    cls=[c for c in d.get_classes() if c.get_name()==TGT]
    if cls:
        print(f"   [定义] {TGT} 方法: {[m.get_name() for m in cls[0].get_methods()]}")
