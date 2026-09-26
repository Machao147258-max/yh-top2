# -*- coding: utf-8 -*-
"""反汇编 sub_264DA0C 与 Oodle 包装 sub_B587284。"""
import capstone
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BD=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
def dis(va, ln, title):
    fo=va-BD
    print(f"\n===== {title} 0x{va:x} (fo 0x{fo:x}) =====")
    for ins in md.disasm(raw[fo:fo+ln], va):
        t=""
        if ins.mnemonic=="bl" and ins.op_str.startswith("#"):
            try: t=f"  -> 0x{int(ins.op_str[1:],16):x}"
            except: pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
dis(0x264DA0C, 0x140, "sub_264DA0C")
dis(0xB587284, 0x100, "Oodle.Decompress wrapper")
