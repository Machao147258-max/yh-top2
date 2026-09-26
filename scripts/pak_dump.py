# -*- coding: utf-8 -*-
"""dump pak footer 原字节 + 逐字节带注释。"""
import struct
PAK = r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
d = open(PAK, "rb").read(); n=len(d)
fo = 0x2f997a6
print(f"文件 {n} 字节, 魔数@0x{fo:x}, 距末尾 {n-fo}")
seg = d[fo:fo+220]
for i in range(0, len(seg), 16):
    off = fo+i
    hx = " ".join(f"{b:02x}" for b in seg[i:i+16])
    asc = "".join(chr(b) if 32<=b<127 else "." for b in seg[i:i+16])
    print(f"0x{off:08x}: {hx:48s} {asc}")
print()
# 再往后到文件末尾
print("=== 末尾 40 字节 ===")
print(" ".join(f"{b:02x}" for b in d[-40:]))
print("ascii:", "".join(chr(b) if 32<=b<127 else "." for b in d[-40:]))
# 头部
print("\n=== 头部 64 字节 ===")
print(" ".join(f"{b:02x}" for b in d[:64]))
