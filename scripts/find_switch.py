# -*- coding: utf-8 -*-
"""反汇编指定函数，找 opcode 跳转表(cmp兜底 + adrp+add表 + ldr/ldrb + br)。"""
import capstone, sys
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail=True

def dis(start,ln):
    fo=start-tb
    ins=list(md.disasm(td[fo:fo+ln], start))
    return ins

FN=int(sys.argv[1],16) if len(sys.argv)>1 else 0x23014
LEN=int(sys.argv[2],16) if len(sys.argv)>2 else 0x8c64
ins=dis(FN,LEN)
print(f"函数 0x{FN:x} 共 {len(ins)} 条")
# 找 br xN
for i,x in enumerate(ins):
    if x.mnemonic=="br":
        ctx="\n".join(f"   0x{y.address:x}: {y.mnemonic} {y.op_str}" for y in ins[max(0,i-8):i+2])
        print("=== br @0x%x ==="%x.address); print(ctx)
# 找 cbz/cbnz + adrp 表
print("\n--- cbz/ldrb/adrp 采样 ---")
c=0
for x in ins:
    if x.mnemonic in ("cbz","cbnz") and c<20:
        print(f"  0x{x.address:x}: {x.mnemonic} {x.op_str}"); c+=1
