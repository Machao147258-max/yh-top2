# -*- coding: utf-8 -*-
"""dump sub_26b1404 引用的常量 0x930950 / 0x9409d0 等。"""
import struct
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
def rd(va,n,note=""):
    print(f"\n0x{va:x} ({note}) {n}B:")
    d=raw[va:va+n]   # rodata: fo==va
    print("  hex:", d.hex())
    print("  ascii:", "".join(chr(b) if 32<=b<127 else '.' for b in d))
    return d
rd(0x930950,32,"sub_26b1404 q0")
rd(0x9409d0,16,"sub_26b1404 d8")
# 附近扫描看有没有像 key 的
print("\n--- 0x930900..0x930a00 ---")
print(raw[0x930900:0x930a00].hex())
print("\n--- 0x940980..0x940a40 ---")
print(raw[0x940980:0x940a40].hex())
