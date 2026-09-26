# -*- coding: utf-8 -*-
"""对每个调 Utils.rL 的方法，解码桩: 提取 Integer(methodId) / Long(salt) / 是否静态 / 数组长度。"""
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
TGT="Lcom/netease/nis/sdkwrapper/Utils;"
rows=[]
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    a,d,dx=AnalyzeDex(os.path.join(D,fn))
    for cls in d.get_classes():
        for m in cls.get_methods():
            code=m.get_code()
            if code is None: continue
            ins=list(code.get_bc().get_instructions())
            txt=" ".join((i.get_output() or "") for i in ins)
            if TGT not in txt: continue
            # 找 Integer.valueOf 前的 const -> methodId; Long.valueOf 前 const-wide -> salt
            mid=None; salt=None; arrlen=None; isstatic = "static" in str(m.get_access_flags_string())
            for k,i in enumerate(ins):
                n=i.get_name(); o=i.get_output() or ""
                if n in ("const/4","const/16","const") and "Integer" in (ins[k+1].get_output() if k+1<len(ins) else ""):
                    mid=int(o.split(",")[-1].strip(),0)
                if n=="const-wide" and "Long" in (ins[k+1].get_output() if k+1<len(ins) else ""):
                    salt=int(o.split(",")[-1].strip(),0)
                if n=="new-array" and "Object" in o:
                    arrlen="reg"
            rows.append((m.get_class_name(), m.get_name(), m.get_descriptor(), isstatic, mid, salt, arrlen))
print(f"共 {len(rows)} 个虚拟化方法")
print(f"{'static':6} {'id':>4} {'salt':>15} {'arr':>3}  method")
for cn,mn,desc,st,mid,salt,al in sorted(rows, key=lambda r:(r[4] if r[4] is not None else -1)):
    print(f"{str(st):6} {str(mid):>4} {str(salt):>15} {str(al):>3}  {cn}->{mn}{desc}")
# 存
import json
json.dump(rows, open(r"C:\Users\20751\Desktop\异环\scripts\rl_methods.json","w"), ensure_ascii=False, indent=1)
