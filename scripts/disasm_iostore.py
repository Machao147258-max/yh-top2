# -*- coding: utf-8 -*-
"""反汇编 IoStore 相关函数 0x2545C8C 区, 找 key/加密处理。"""
import capstone
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BD=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
def dis(va, ln, title):
    print(f"\n===== {title} 0x{va:x} =====")
    for ins in md.disasm(raw[va-BD:va-BD+ln], va):
        t=""
        if ins.mnemonic in ("bl","b","cbz","cbnz","tbz","tbnz") and ins.op_str.startswith("#"):
            t=""
        if ins.mnemonic in ("bl","b"):
            try: t=f"  -> 0x{int(ins.op_str.split('#')[-1],16):x}"
            except: pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
dis(0x2545C8C, 0x120, "IoStore sub_2545C8C")
