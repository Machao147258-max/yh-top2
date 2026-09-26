# -*- coding: utf-8 -*-
"""dump 指定方法的完整指令，看方法体是否变成 rL 桩。"""
import os,sys
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
a,d,dx=AnalyzeDex(r"C:\Users\20751\Desktop\异环\unpacked\dex\classes.dex")
def dump(cls,meth):
    for m in dx.find_methods(classname=cls, methodname=meth):
        em=m.get_method(); code=em.get_code()
        print(f"\n=== {cls}->{meth} ({'无码' if code is None else str(len(list(code.get_bc().get_instructions())))+' 条'}) ===")
        if code is None: continue
        for ins in code.get_bc().get_instructions():
            print(f"   {ins.get_name():28s} {ins.get_output()}")
dump("Lcom/bun/miitmdid/provider/BaseProvider;","getOAID")
dump("Lcom/bun/miitmdid/core/MdidSdkHelper;","logd")
dump("Lcom/bun/miitmdid/provider/DefaultProvider;","isSupported")
