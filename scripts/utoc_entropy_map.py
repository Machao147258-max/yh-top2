# -*- coding: utf-8 -*-
"""utoc 分段熵图 (每 0x2000 一段)。"""
import os, math, collections
IO=r"C:\Users\20751\Desktop\异环\unpacked\io"
def H(bs):
    c=collections.Counter(bs); n=len(bs)
    return -sum(v/n*math.log2(v/n) for v in c.values()) if n else 0
for name in ("pakchunk0-Android_ASTC.utoc",):
    p=os.path.join(IO,name); d=open(p,"rb").read()
    print(f"{name} {len(d)}B, 每0x2000一段熵:")
    step=0x2000
    for off in range(0, len(d), step):
        seg=d[off:off+step]
        print(f"  0x{off:07x}: H={H(seg):.3f}  (n={len(seg)})")
