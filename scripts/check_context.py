# -*- coding: utf-8 -*-
"""核实可疑单次命中：打印命中处上下文字符串。"""
import os
SO_DIR = r"C:\Users\20751\Desktop\异环\unpacked\so"
CHECKS = {
    "libclient.so": [b"Frida", b"VmP", b"ptrace", b"PTRACE", b"tracer"],
    "libDfga_Catch.so": [b"Frida", b"VmP", b"PTRACE", b"native_testCrash"],
    "libthemis.so": [b"https://"],
}
def ctx(d, i, w=40):
    a=max(0,i-w); b=min(len(d),i+w)
    seg=d[a:b]
    return "".join(chr(c) if 32<=c<127 else "." for c in seg)
for name, pats in CHECKS.items():
    d=open(os.path.join(SO_DIR,name),"rb").read()
    print(f"\n### {name}")
    for p in pats:
        i=d.find(p)
        n=d.count(p)
        if i<0: 
            print(f"  {p.decode()}: 无"); continue
        print(f"  {p.decode()} ×{n} @0x{i:x}: ...{ctx(d,i)}...")
