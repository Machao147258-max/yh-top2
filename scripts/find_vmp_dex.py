# -*- coding: utf-8 -*-
"""在 libsecsdk.so 里找 VMP/DEX 相关字符串 + 找内嵌 DEX。"""
import re
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); data=open(SO,"rb").read()

# 1) 关键字符串
print("=== 关键字串 ===")
for kw in [b"mutivmp", b"src/mai", b".version.sdk", b"pHeader", b"pDexFile",
           b"DexPathList", b"BaseDexClassLoader", b"dexElements", b"loadClass",
           b"dex\n", b"dex\n035", b"dex\n036", b"dex\n038", b"dex\n039"]:
    idxs=[m.start() for m in re.finditer(re.escape(kw), data)][:5]
    print(f"  {kw}: {[hex(i) for i in idxs]} ({len(idxs)})")

# 2) 找 DEX magic 'dex\n0' (64 39 65 78 0a)
print("\n=== 找内嵌 DEX (magic 'dex\\n0xx') ===")
for m in re.finditer(rb"dex\n0\d\d", data):
    off=m.start(); print(f"  dex magic @ file 0x{off:x}")
    if off>16:
        print("   前置:", data[off-16:off])

# 3) 找 '2e 76 65 72 73 69 6f 6e' = ".version" 附近
i=data.find(b".version")
print(f"\n=== .version @0x{i:x} 附近 ===")
if i>0: print("  ", data[i-40:i+40])
f.close()
