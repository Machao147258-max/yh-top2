# -*- coding: utf-8 -*-
"""libsecsdk: 全部导出符号 + .rodata 全部字符串。"""
import re
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
dynsym=elf.get_section_by_name('.dynsym')
exps=[s.name for s in dynsym.iter_symbols() if s['st_shndx']!='SHN_UNDEF' and s.name]
print(f"=== 全部导出 ({len(exps)}) ===")
for e in exps: print("  ",e)
# .rodata 字符串
rd=elf.get_section_by_name('.rodata'); base=rd['sh_addr']; d=rd.data()
print(f"\n=== .rodata 字符串 (0x{base:x}, {len(d)}字节) ===")
for m in re.finditer(rb"[\x20-\x7e]{2,}", d):
    print(f"  0x{base+m.start():x}: {m.group().decode('latin1')}")
# .data 里也可能是字符串/表
dt=elf.get_section_by_name('.data'); db=dt['sh_addr']; dd=dt.data()
print(f"\n=== .data 可读串 (0x{db:x}) ===")
for m in re.finditer(rb"[\x20-\x7e]{3,}", dd):
    print(f"  0x{db+m.start():x}: {m.group().decode('latin1')[:80]}")
f.close()
