# -*- coding: utf-8 -*-
"""细化 classes5 高熵区边界 + hexdump。"""
import math
from collections import Counter
p=r"C:\Users\20751\Desktop\异环\unpacked\dex\classes5.dex"
b=open(p,"rb").read()
def H(x):
    if not x: return 0
    c=Counter(x); n=len(x); return -sum((v/n)*math.log2(v/n) for v in c.values())
# 256B 细扫 0x720000-0x72b000
print("=== 256B 熵 (0x720000-0x72b000) ===")
cur=None
for off in range(0x720000,0x72b000,256):
    e=H(b[off:off+256])
    mark="HI" if e>6.5 else "  "
    if mark=="HI" or (cur and off%0x1000==0): print(f" 0x{off:x} H={e:.2f} {mark}")
# 精确找边界: 从 0x700000 起逐 256
runs=[]
inrun=False; st=0
for off in range(0x700000,0x730000,256):
    e=H(b[off:off+256])
    hi=e>7.0
    if hi and not inrun: inrun=True; st=off
    if not hi and inrun: inrun=False; runs.append((st,off))
if inrun: runs.append((st,0x730000))
print("\n高熵区间:", [(hex(a),hex(b)) for a,b in runs])
for a,b2 in runs:
    print(f"\n--- 0x{a:x} 头部 64B ---")
    print(b[a:a+64].hex())
    print(repr(b[a:a+48]))
