# -*- coding: utf-8 -*-
"""找引用反调试串的类/方法。"""
import os
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.misc import AnalyzeDex
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
TARGETS=["TracerPid","isRooted","/dev/qemu_pipe","/dev/socket/qemud","ro.kernel.qemu","de.robv.android.xposed.XposedBridge","/proc/self/maps","/proc/self/status","/proc/self/mountinfo","/sbin/su","/proc/self/net/tcp"]
for fn in ["classes5.dex","classes4.dex","classes3.dex"]:
    a,d,dx=AnalyzeDex(os.path.join(D,fn))
    print(f"\n==== {fn} ====")
    found={}
    for c in d.get_classes():
        for m in c.get_methods():
            if m.get_code() is None: continue
            try:
                for ins in m.get_instructions():
                    if ins.get_name().startswith("const-string"):
                        v=ins.get_output()
                        for t in TARGETS:
                            if '"'+t+'"' in v or t in v:
                                found.setdefault(t,set()).add(c.get_name()+"->"+m.get_name())
            except Exception:
                pass
    for t in TARGETS:
        if t in found:
            print(f"  [{t}]")
            for s in sorted(found[t])[:6]: print("     "+s[:120])
