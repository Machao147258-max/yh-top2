# -*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
f=open(r"D:\qwork\libsecsdk.so","rb"); elf=ELFFile(f)
for sec in ('.symtab','.dynsym'):
    s=elf.get_section_by_name(sec)
    if not s: 
        print(sec,"无"); continue
    syms=[sym for sym in s.iter_symbols() if sym.name]
    print(f"=== {sec}: {len(syms)} 具名符号 ===")
    for sym in syms:
        if sym['st_info']['type']=='STT_FUNC':
            print(f"  FUNC {sym.name}  @0x{sym['st_value']:x} size=0x{sym['st_size']:x}")
    # 非 FUNC 里含 func/vmp/cd 的
    for sym in syms:
        n=sym.name
        if sym['st_info']['type']!='STT_FUNC' and any(k in n for k in ('.cd','Interpret','vmp','Dex','cd0','cd1')):
            print(f"  OBJ  {n} @0x{sym['st_value']:x}")
f.close()
