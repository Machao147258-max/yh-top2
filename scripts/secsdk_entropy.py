# -*- coding: utf-8 -*-
"""libsecsdk: 段布局 + 熵图 + 内嵌.so/.dex文件名 + raw-deflate尝试。"""
import re, zlib, math
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
print("=== 段 ===")
for s in elf.iter_segments():
    if s['p_type']=='PT_LOAD':
        d=raw[s['p_offset']:s['p_offset']+s['p_filesz']]
        # 熵
        if d:
            from collections import Counter
            c=Counter(d); H=-sum((n/len(d))*math.log2(n/len(d)) for n in c.values())
        else: H=0
        print(f"  vaddr=0x{s['p_vaddr']:x} off=0x{s['p_offset']:x} filesz=0x{s['p_filesz']:x} flags={s['p_flags']} 熵={H:.2f}")
print("=== 节 ===")
for sec in elf.iter_sections():
    if sec['sh_size']>0x1000:
        print(f"  {sec.name}: addr=0x{sec['sh_addr']:x} size=0x{sec['sh_size']:x}")
# 内嵌文件名
print("\n=== 内嵌文件名字符串 ===")
for m in re.finditer(rb"[\x20-\x7e]{3,}\.(so|dex|dat|bin|jar|apk|odex|oat|png|json)\b", raw):
    print(f"  0x{m.start():x}: {m.group().decode('latin1')}")
# .so/.dex 路径
print("\n=== 路径串 ===")
for m in re.finditer(rb"/[a-zA-Z0-9_./-]{4,}", raw):
    s=m.group().decode('latin1')
    if any(k in s for k in ('/system','/data','/proc','/dev','/vendor','/apex','/sdcard','/storage')): print("  ",s)
# 高熵块(可能的压缩/加密载荷)
print("\n=== 高熵块 (>7.5, 4KB 窗) ===")
W=4096; from collections import Counter
for off in range(0, len(raw)-W, W):
    d=raw[off:off+W]; c=Counter(d); H=-sum((n/W)*math.log2(n/W) for n in c.values())
    if H>7.5: print(f"  0x{off:x}: 熵={H:.2f}")
f.close()
