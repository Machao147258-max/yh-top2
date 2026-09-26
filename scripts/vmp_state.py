# -*- coding: utf-8 -*-
"""从 libsecsdk JNI_OnLoad 提取 VMP 状态机: 状态常量(mov/movk), 分发(cmp + b.eq), 回边(b 到分发器)。"""
import capstone
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
fo=0xb1b0-tb
insns=list(md.disasm(td[fo:fo+0x600], 0xb1b0))
# 1) 收集寄存器常量: mov wX,#lo ; movk wX,#hi,lsl#16
consts={}
for ins in insns:
    p=ins.op_str.split(',')
    try:
        if ins.mnemonic=="mov" and len(p)==2 and p[0].strip().startswith('w'):
            consts[p[0].strip()]=int(p[1].split('#')[1],16)
        elif ins.mnemonic=="movk":
            reg=p[0].strip(); hi=int(p[1].split('#')[1],16)
            if reg in consts: consts[reg]=(consts[reg]&0xFFFF)|(hi<<16)
    except: pass
print("=== 32位状态/比较常量(寄存器=值) ===")
for r,v in consts.items():
    if v>0xFFFF: print(f"  {r} = 0x{v:08x}")
# 2) 分发: cmp w8, wY ; 后跟 b.xx target
print("\n=== 分发点 (cmp w8,<const> + 跳转) ===")
for i,ins in enumerate(insns):
    if ins.mnemonic=="cmp" and ins.op_str.startswith("w8,"):
        cst=ins.op_str.split(',')[1].strip()
        val=consts.get(cst)
        tgt=''
        for j in (i+1,i+2):
            if j<len(insns) and insns[j].mnemonic.startswith('b.') or (j<len(insns) and insns[j].mnemonic=='b'):
                try: tgt=f"{insns[j].mnemonic} 0x{int(insns[j].op_str.split('#')[1],16):x}"
                except: tgt=insns[j].mnemonic
                break
        if val: print(f"  0x{ins.address:x}: cmp w8, {cst}(=0x{val:08x})  → {tgt}")
# 3) 回边: b 到分发器 0xb258
print("\n=== 回边(设新 state 后 b 到分发器 0xb258) ===")
for ins in insns:
    if ins.mnemonic=="b":
        try:
            if int(ins.op_str.split('#')[1],16)==0xb258: print(f"  0x{ins.address:x}: b 0xb258")
        except: pass
print(f"\n分发器地址 = 0xb258; 状态常量数 = {sum(1 for v in consts.values() if v>0xFFFF)}")
f.close()
