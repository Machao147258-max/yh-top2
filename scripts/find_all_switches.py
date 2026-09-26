# -*- coding: utf-8 -*-
"""全 .text 扫描 opcode 跳转表：找 'ldr/ldrb reg,[base, idx, lsl]' + 'br reg' 组合。"""
import capstone, re
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(td, tb))
print("总指令", len(ins))
brs=[i for i,x in enumerate(ins) if x.mnemonic=="br"]
print("br 数:", len(brs))
def istable(x):
    # ldr/ldrb/ldrh with [reg, reg, lsl #..]
    return x.mnemonic in ("ldr","ldrb","ldrh","ldrsw") and re.search(r"\[x\d+, x\d+", x.op_str)
found=0
for i in brs:
    win=ins[max(0,i-7):i+1]
    if any(istable(y) for y in win):
        found+=1
        print(f"\n=== jumptable br @0x{ins[i].address:x} ===")
        for y in win: print(f"   0x{y.address:x}: {y.mnemonic} {y.op_str}")
        if found>=25: break
print("\n带表 br 组合数(前25):", found)
