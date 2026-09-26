# -*- coding: utf-8 -*-
"""反汇编 libsecsdk 的 rL 本体 @0xaddc + 周边。"""
import capstone
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
for start,ln in [(0xaddc,0x90)]:
    print(f"=== rL @0x{start:x} ===")
    fo=start-tb
    for ins in md.disasm(td[fo:fo+ln], start):
        t=f"{ins.mnemonic} {ins.op_str}"
        if ins.mnemonic in ("bl","b"):
            try: t+=" ->0x%x"%int(ins.op_str.split('#')[1],16)
            except: pass
        if ins.mnemonic=="svc": t+="   <<< svc"
        print(f"0x{ins.address:x}: {t}")
f.close()
