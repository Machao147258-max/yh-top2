# -*- coding: utf-8 -*-
"""扫 .text: 邻近 'mov w0,#0x50'(alloc) 的 'str reg,[reg,#0x40]' —— methodInfo+0x40 写入点。"""
import capstone,re
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(td, tb))
# 找 alloc 0x50 的位置
allocs=[]
for i,x in enumerate(ins):
    if x.mnemonic=="mov" and re.match(r"w0, #0x(50|48|58|60)$", x.op_str): allocs.append(i)
print("alloc(0x50/48/58/60) 点:", [hex(ins[i].address) for i in allocs])
# 找 +0x40 store, 且前 80 条内有 alloc
for i,x in enumerate(ins):
    if x.mnemonic=="str" and re.search(r"\[x\d+, #0x40\]", x.op_str):
        near=[a for a in allocs if 0<i-a<=80]
        if near:
            print(f"\n=== str [#0x40] @0x{x.address:x}  {x.op_str}  (alloc @0x{ins[near[-1]].address:x}) ===")
            for y in ins[max(0,i-6):i+3]:
                print(f"   0x{y.address:x}: {y.mnemonic} {y.op_str}")
