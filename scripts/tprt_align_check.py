# -*- coding: utf-8 -*-
"""从 .text 起点正确对齐反汇编, 看 0x269e0 真身。"""
import capstone
from elftools.elf.elffile import ELFFile
P=r'D:\qwork\libtprt.so'
elf=ELFFile(open(P,'rb'))
txt=elf.get_section_by_name('.text')
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
n=0
for x in md.disasm(txt.data(), txt['sh_addr']):
    if 0x269c0<=x.address<=0x269f0:
        print('0x%x %-8s %s'%(x.address,x.mnemonic,x.op_str))
    if x.address>0x269f0: break
# 对比: disasm_range.py 是从 around-0x18 起 -> 错位
print('--- 从 0x269c8 直接起(错位) ---')
data=txt.data(); base=txt['sh_addr']
for x in md.disasm(data[0x269c8-base:0x269c8-base+0x40], 0x269c8):
    print('0x%x %-8s %s'%(x.address,x.mnemonic,x.op_str))
