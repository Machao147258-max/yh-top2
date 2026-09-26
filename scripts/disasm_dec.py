# -*- coding: utf-8 -*-
"""反汇编解密指针指向的两个候选函数 0x267BF30 / 0x267FD08。"""
import capstone
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BD=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
def dis(va, ln, title):
    print(f"\n===== {title} 0x{va:x} (fo 0x{va-BD:x}) =====")
    for ins in md.disasm(raw[va-BD:va-BD+ln], va):
        t=""
        if ins.mnemonic=="bl" and ins.op_str.startswith("#"):
            try: t=f"  -> sub_0x{int(ins.op_str[1:],16):x}"
            except: pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
dis(0x267BF30, 0x140, "dec_fn(ctor#19 设置)")
dis(0x267FD08, 0x80, "dec_fn(初值)")
