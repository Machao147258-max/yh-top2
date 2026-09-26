# -*- coding: utf-8 -*-
"""androguard 分析层：找 Utils.rL 真实调用者。"""
import os, logging
logging.getLogger("androguard").setLevel(logging.CRITICAL)
import warnings; warnings.filterwarnings("ignore")
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
TGT="Lcom/netease/nis/sdkwrapper/Utils;"
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    p=os.path.join(D,fn)
    try:
        a,d,dx=AnalyzeDex(p)
    except Exception as e:
        print(f"[{fn}] 解析失败 {e}"); continue
    tot=0; callers={}
    for meth in ["rL","showRiskMessage","doTypeShort","getFieldSCDesc","getStaticFO","vGetFieldSCDesc"]:
        for m in dx.find_methods(classname=TGT, methodname=meth):
            xf=list(m.get_xref_from())
            tot+=len(xf)
            print(f"\n[{fn}] {TGT}->{meth}: {len(xf)} 调用点")
            for cls,mm,off in xf[:30]:
                key=str(mm)
                callers[key]=callers.get(key,0)+1
                print(f"    <- {key} @0x{off:x}")
    if tot:
        print(f"\n[{fn}] 汇总(方法->次数):")
        for k,v in sorted(callers.items(),key=lambda x:-x[1]): print(f"   {v:3d}  {k}")
