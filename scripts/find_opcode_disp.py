# -*- coding: utf-8 -*-
import capstone, re
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(td, tb))
print("总指令",len(ins))
print("=== cmp wN,#0xff / #0x100 ===")
for i,x in enumerate(ins):
    if x.mnemonic=="cmp" and ("#0xff" in x.op_str or "#0x100" in x.op_str or "#255" in x.op_str or "#256" in x.op_str):
        for y in ins[max(0,i-2):i+4]: print(f"  0x{y.address:x}: {y.mnemonic} {y.op_str}")
        print("  ---")
# 找最大跳转表边界
print("=== 所有 br 的边界值 ===")
brs=[i for i,x in enumerate(ins) if x.mnemonic=="br"]
import collections
for i in brs:
    win=ins[max(0,i-8):i]
    for y in win:
        if y.mnemonic=="cmp" and "#" in y.op_str:
            print(f"  br@0x{ins[i].address:x} bound: {y.op_str}")
            break
