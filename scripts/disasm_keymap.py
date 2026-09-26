# -*- coding: utf-8 -*-
"""反汇编 sub_26b1404 (构造/填充 key map) —— 找 key 字节。"""
import capstone
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BD=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
def dis(va, ln, title):
    print(f"\n===== {title} 0x{va:x} =====")
    for ins in md.disasm(raw[va-BD:va-BD+ln], va):
        t=""
        if ins.mnemonic in ("bl","b") and ins.op_str.startswith("#"):
            try: t=f"  -> 0x{int(ins.op_str[1:],16):x}"
            except: pass
        # 标注 adrp+add 立即数
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
dis(0x26b1404, 0x200, "sub_26b1404 (key map 填充)")
