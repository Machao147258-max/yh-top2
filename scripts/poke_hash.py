# -*- coding: utf-8 -*-
"""暴力: 找 pak 里 SHA1==eda462... 的字节范围。"""
import hashlib
PAK=r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
d=open(PAK,"rb").read()
T="eda462f54e6b194fa3474b5791dfab404b95ca7b"
def h(b): return hashlib.sha1(b).hexdigest()
# 已知
print("SHA1(idx 0x2f41376,0x11320) =", h(d[0x2f41376:0x2f41376+0x11320]), "==", h(d[0x2f41376:0x2f41376+0x11320])==T)
# 尝试各种 size
for sz in (0x11320,0x11320-16,0x11320+16,0x11320+204,0x11320+204+16,0x11000,0x10000):
    print(f"  size={sz:#x}:", h(d[0x2f41376:0x2f41376+sz]) )
# 尝试各种 offset
for off in (0x2f41376-16,0x2f41376+16,0x2f41376-204,0x2f41376+204):
    print(f"  off={off:#x} size=0x11320:", h(d[off:off+0x11320]))
# 全文件滑窗找(粗):只在索引附近
import struct
m=hashlib.sha1
lo,hi=0x2f40000,0x2f99800
found=False
for off in range(lo,hi,16):   # 粗步长
    if m(d[off:off+0x11320]).hexdigest()==T:
        print("命中 off=",hex(off)); found=True; break
print("滑窗(步长16)结果:", "命中"+hex(off) if found else "无")
# 也许 hash 是 md5? 试几种
import hashlib as H
for name in ("md5","sha1","sha256"):
    for off,sz in [(0x2f41376,0x11320)]:
        print(f"{name}(idx)=", getattr(H,name)(d[off:off+sz]).hexdigest())
