# -*- coding: utf-8 -*-
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
TARGETS=["TracerPid","/proc/self/maps","/proc/self/status","/proc/self/mountinfo"]
def find(fn):
    a,d,dx=AnalyzeDex(os.path.join(D,fn))
    res=[]
    for c in d.get_classes():
        for m in c.get_methods():
            if m.get_code() is None: continue
            try:
                for ins in m.get_instructions():
                    if ins.get_name().startswith("const-string"):
                        v=ins.get_output()
                        for t in TARGETS:
                            if '"'+t+'"' in v:
                                res.append((t,c.get_name(),m.get_name(),m.get_descriptor()))
            except Exception: pass
    return res
for fn in ["classes5.dex","classes4.dex","classes3.dex"]:
    for r in find(fn):
        print(f"[{fn[:9]}] {r[0]}  <-  {r[1]}->{r[2]}{r[3]}")
