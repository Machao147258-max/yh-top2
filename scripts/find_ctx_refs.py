# -*- coding: utf-8 -*-
"""扫 .text 里引用全局 0x64d30 (VM上下文单例) 的指令。"""
import capstone,re
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(td, tb))
TARGET=0x64d30
adrp={}
print("=== 引用 0x64d30 的指令 ===")
for x in ins:
    if x.mnemonic=="adrp":
        m=re.search(r"x(\d+), #0x([0-9a-f]+)", x.op_str)
        if m: adrp[int(m.group(1))]=int(m.group(2),16)
    else:
        # 任意内存访问 [xN, #imm] 或 [xN]
        for r,imm in re.findall(r"\[x(\d+)(?:, #(0x[0-9a-f]+))?\]", x.op_str):
            r=int(r); imm=int(imm,16) if imm else 0
            if r in adrp and adrp[r]+imm==TARGET:
                print(f"  0x{x.address:x}: {x.mnemonic} {x.op_str}")
                break
