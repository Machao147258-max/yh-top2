# -*- coding: utf-8 -*-
"""反汇编 sub_3AC7CA8 (索引解密函数), 解析 bl 目标与常量。"""
import capstone, struct
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BASE_DIFF=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail=True
def dis(va, ln, title=""):
    fo=va-BASE_DIFF
    print(f"\n===== {title} 0x{va:x} (fo 0x{fo:x}) =====")
    for ins in md.disasm(raw[fo:fo+ln], va):
        tgt=""
        if ins.mnemonic=="bl" and ins.op_str.startswith("#"):
            try: tgt=f"  -> sub_0x{int(ins.op_str[1:],16):x}"
            except: pass
        # adrp/add 目标
        if ins.mnemonic in ("adrp",):
            tgt="   (adrp)"
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{tgt}")
dis(0x3AC7CA8, 0x180, "索引解密函数")
