# -*- coding: utf-8 -*-
"""反汇编 footer 解析器 0x3AD7C70。"""
import capstone
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BD=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
for ins in md.disasm(raw[0x3AD7C70-BD:0x3AD7C70-BD+0x300], 0x3AD7C70):
    t=""
    if ins.mnemonic in ("bl","b") and ins.op_str.startswith("#"):
        try: t=f"  -> 0x{int(ins.op_str[1:],16):x}"
        except: pass
    print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
