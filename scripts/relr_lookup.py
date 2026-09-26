# -*- coding: utf-8 -*-
"""解析 RELR, 查出 .data.rel.ro 中指定位置的指针目标(解密函数)。"""
import struct
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libUnreal.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
dyn=elf.get_section_by_name('.dynamic'); DT={t.entry.d_tag:t.entry.d_val for t in dyn.iter_tags()}
relr_off=DT['DT_ANDROID_RELR']; relr_sz=DT['DT_ANDROID_RELRSZ']
entries=[struct.unpack_from("<Q",raw,relr_off+i*8)[0] for i in range(relr_sz//8)]
locs=[]; where=0
for e in entries:
    if e&1==0: where=e; locs.append(where); where+=8
    else:
        for i in range(63):
            if e&(2<<i): locs.append(where+i*8)
        where+=63*8
locset=set(locs)
def segfo(va):
    for seg in elf.iter_segments():
        if seg['p_type']!='PT_LOAD': continue
        v=seg['p_vaddr']
        if v<=va<v+seg['p_filesz']: return seg['p_offset']+(va-v)
    return None
def lookup(va):
    if va not in locset: return None
    fo=segfo(va)
    if fo is None: return None
    return struct.unpack_from("<Q",raw,fo)[0]   # addend = 目标VA
for va in (0xe1ec250,0xe1ec248,0xe1ec258,0xe1ec260):
    t=lookup(va)
    print(f"[0x{va:x}] = 0x{t:x}" if t is not None else f"[0x{va:x}] 非相对重定位")
# 也看看这些目标是不是已知函数(sub_xxx)
for va in (0xe1ec250,):
    t=lookup(va)
    print(f"\n=> 解密函数 = 0x{t:x}" if t else "")
