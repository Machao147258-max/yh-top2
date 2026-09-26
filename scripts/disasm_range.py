# -*- coding: utf-8 -*-
"""通用反汇编区间。<start_hex> <len_hex> [so_path]"""
import capstone, sys
from elftools.elf.elffile import ELFFile
SO=sys.argv[3] if len(sys.argv)>3 else r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
start=int(sys.argv[1],16); ln=int(sys.argv[2],16)
n=int(sys.argv[4]) if len(sys.argv)>4 else 0
fo=start-tb
ins=list(md.disasm(td[fo:fo+ln], start))
if n: ins=ins[:n]
for x in ins:
    t=f"{x.mnemonic} {x.op_str}"
    if x.mnemonic in ("bl","b","b.eq","b.ne","b.hi","b.lo","b.ge","b.le","b.gt","b.lt"):
        s=x.op_str.replace('#','')
        try: t+="  ->0x%x"%int(s,16)
        except: pass
    print(f"0x{x.address:x}: {t}")
