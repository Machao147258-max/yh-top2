# -*- coding: utf-8 -*-
"""提取 DEX-VMP opcode 跳转表 @0x48b30 (256 x int32 相对偏移)。"""
import struct, capstone
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=open(SO,"rb").read()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
TBL=0x48b30
base=TBL
targets={}
for op in range(256):
    val=struct.unpack_from("<i", td, TBL+op*4)[0]
    targets[op]=base+val
# 统计唯一 handler
uniq=sorted(set(targets.values()))
print(f"表@0x{TBL:x}: 256 项, 唯一 handler {len(uniq)} 个")
# 打印 opcode -> handler
for op in range(256):
    # 每个 handler 第一条指令
    fo=targets[op]-tb
    ins=next(md.disasm(td[fo:fo+8], targets[op]), None)
    txt_i=f"{ins.mnemonic} {ins.op_str}" if ins else "?"
    print(f"  op 0x{op:02x} ({op:3d}) -> 0x{targets[op]:x}   {txt_i}")
# 保存
with open(r"C:\Users\20751\Desktop\异环\reports\opcode_table_48b30.txt","w") as w:
    for op in range(256):
        w.write(f"0x{op:02x} 0x{targets[op]:x}\n")
