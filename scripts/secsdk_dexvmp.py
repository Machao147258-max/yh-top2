# -*- coding: utf-8 -*-
"""libsecsdk: 1)找DEX载荷 2)爆破.data异或串 3)确认DEX-VMP。"""
import re, zlib
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
# 1) DEX magic
print("=== 找 DEX 载荷 ===")
for magic in (b"dex\n", b"dey\n", b"odex"):
    for m in re.finditer(re.escape(magic), raw):
        print(f"  {magic} @ 0x{m.start():x}: {raw[m.start():m.start()+32]!r}")
# .data 区
dt=elf.get_section_by_name('.data'); dd=dt.data(); db=dt['sh_addr']
print(f"\n.data: 0x{db:x}..0x{db+len(dd):x} ({len(dd)}字节)")
# 2) 爆破异或
def is_print(b):
    return sum(32<=c<127 or c in (9,10,13) for c in b)/len(b) > 0.9
print("\n=== .data 单字节异或爆破 (候选) ===")
best=[]
for key in range(1,256):
    dec=bytes(c^key for c in dd)
    # 数可打印且含空格/字母的英文片段
    runs=re.findall(rb"[ -~]{6,}", dec)
    good=[r for r in runs if len(r)>=8 and b" " in r and sum(65<=c<=122 for c in r)/len(r)>0.7]
    if good:
        best.append((key,good))
for key,good in best[:12]:
    print(f"  key=0x{key:02x}:")
    for g in good[:6]: print(f"     {g[:70]!r}")
# 3) 确认解释器: 引用了哪些 dex* 串的代码位置
print("\n=== DEX 解释器证据 (串偏移) ===")
for kw in (b"DexStringId",b"DexMethodId",b"InterpretInternal",b"VmHelper",b"NativeMethodParser",b"ConfigManager",b"SeparatorData"):
    i=raw.find(kw)
    print(f"  {kw}: @0x{i:x}")
f.close()
