# -*- coding: utf-8 -*-
"""查 GOT 0x610dd8 对应哪个导入符号 + 列所有 libsecsdk 的 C++ new/delete 导入。"""
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); dyn=elf.get_section_by_name('.dynsym')
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection):
        for rel in sec.iter_relocations():
            if rel['r_offset']==0x610dd8:
                print(f"GOT 0x610dd8 -> {dyn.get_symbol(rel['r_info_sym']).name} ({sec.name} type={rel['r_info_type']})")
print("\n所有 undef 导入:")
for s in dyn.iter_symbols():
    if s.name and s['st_shndx']=='SHN_UNDEF': print("  ",s.name)
f.close()
