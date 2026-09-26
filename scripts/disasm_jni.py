# -*- coding: utf-8 -*-
"""libsecsdk: 解 JNI_OnLoad, 标出对 JNIEnv/JVM 函数表项的调用(ldr xN,[xM,#off]; blr)."""
import capstone
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
fo=0xb1b0-tb
print("=== JNI_OnLoad 反汇编 (标出表项 load/blr) ===")
for ins in md.disasm(td[fo:fo+0x180], 0xb1b0):
    t=f"{ins.mnemonic} {ins.op_str}"
    mark=""
    if ins.mnemonic=="ldr" and "x8" in ins.op_str and "[x8" in ins.op_str:
        try: mark="  ; 表项 idx=0x%s/8=%d"%((ins.op_str.split('#')[1].rstrip(']')), int(ins.op_str.split('#')[1].rstrip(']'),16)//8)
        except: mark="  ; 表项"
    if ins.mnemonic=="blr": mark="  <<< 间接调用(JNI)"
    if ins.mnemonic in ("bl","b"):
        try: t+=" ->0x%x"%int(ins.op_str.split('#')[1],16)
        except: pass
    print(f"0x{ins.address:x}: {t}{mark}")
f.close()
