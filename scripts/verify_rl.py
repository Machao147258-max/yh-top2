# -*- coding: utf-8 -*-
"""解码实际指令：验证 miitmdid 是否真调 Utils.rL。"""
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
p=r"C:\Users\20751\Desktop\异环\unpacked\dex\classes.dex"
a,d,dx=AnalyzeDex(p)
TGT="Lcom/netease/nis/sdkwrapper/Utils;"
for m in dx.find_methods(classname=TGT, methodname="rL"):
    print("方法:", m.get_method().get_class_name(), m.get_method().get_name(), m.get_method().get_descriptor())
    xf=list(m.get_xref_from())
    print("xref 数:", len(xf))
    # 打印前 3 个 caller 的实际指令里，指向 Utils.rL 的那条
    for cls,mm,off in xf[:3]:
        em=mm.get_method()
        print(f"\n--- caller {em.get_class_name()}->{em.get_name()} (xref@0x{off:x}) ---")
        code=em.get_code()
        if code is None: print("  无代码"); continue
        for ins in code.get_bc().get_instructions():
            if ins.get_name().startswith("invoke"):
                print("   ", ins.get_name(), ins.get_output())
    # 统计所有 xref 的 caller 类前缀
    from collections import Counter
    c=Counter()
    for cls,mm,off in xf:
        c[mm.get_method().get_class_name().split("/")[2] if len(mm.get_method().get_class_name().split("/"))>2 else "?"]+=1
    print("\ncaller 包分布:", dict(c))
