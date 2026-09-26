# -*- coding: utf-8 -*-
"""诊断 libUnreal.so 的动态重定位段。"""
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import collections
SO=r"D:\qwork\libUnreal.so"
f=open(SO,"rb"); elf=ELFFile(f)
print("所有重定位段:")
for sec in elf.iter_sections():
    if isinstance(sec, RelocationSection):
        hist=collections.Counter()
        n=0
        for rel in sec.iter_relocations():
            hist[rel['r_info_type']]+=1; n+=1
        rel="RELA" if sec.is_RELA() else "REL"
        print(f"  {sec.name} ({rel}) entries={n} types={dict(hist)}")

# 动态段里有没有 .rela.dyn 线索
dyn = elf.get_section_by_name('.dynamic')
if dyn:
    print("\nDT_* 里 RELA 相关:")
    for tag in dyn.iter_tags():
        if 'RELA' in tag.entry.d_tag or 'REL' in tag.entry.d_tag or 'JMPREL' in tag.entry.d_tag:
            print(f"  {tag.entry.d_tag} = {tag.entry.d_val}")
f.close()
