# -*- coding: utf-8 -*-
import capstone, re
from elftools.elf.elffile import ELFFile
P=r'D:\qwork\libtprt.so'
elf=ELFFile(open(P,'rb'))
txt=elf.get_section_by_name('.text')
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
# 只看 0x269d8..0x26b00 窗口
data=txt.data(); base=txt['sh_addr']
win=data[0x269d8-base:0x26b40-base]
xreg={}; wreg={}; K={}
for x in md.disasm(win, 0x269d8):
    print('0x%x %-8s %s'%(x.address,x.mnemonic,x.op_str))
