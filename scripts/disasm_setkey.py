# -*- coding: utf-8 -*-
import capstone
raw = open(r"D:\qwork\libUnreal.so", "rb").read()
VA = 0xABFA760
FO = VA - 0x4000
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
for ins in md.disasm(raw[FO:FO+0x80], VA):
    print("0x%x: %s %s" % (ins.address, ins.mnemonic, ins.op_str))
