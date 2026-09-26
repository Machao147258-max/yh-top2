# -*- coding: utf-8 -*-
raw=open(r"D:\qwork\libsecsdk.so","rb").read()
def s(va,n=64):
    seg=raw[va:va+n].split(b"\x00")[0]
    return ''.join(chr(c) if 32<=c<127 else '.' for c in seg)
# 从仿真: x0=0x5555555b60e0 (va=0x620e0) x2=0x55555559adb0 (va=0x46db0)
for va in (0x620E0,0x46DB0,0x620e0-0x40):
    print(f"0x{va:x}: {s(va)!r}")
# 也扫 JNI_OnLoad 引用的串
import struct,capstone
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
print("\nJNI_OnLoad 前 0x100 里的串引用:")
adrp={}
for ins in md.disasm(raw[0xb1b0:0xb1b0+0x180],0xb1b0):
    if ins.mnemonic=="adrp":
        try: adrp[ins.op_str.split(',')[0]]=int(ins.op_str.split('#')[1],16)
        except: pass
    if ins.mnemonic=="add":
        p=ins.op_str.split(',')
        if len(p)==3 and p[1].strip() in adrp:
            try:
                va=adrp[p[1].strip()]+int(p[2].split('#')[1],16)
                print(f"  0x{ins.address:x}: =0x{va:x} {s(va,40)!r}")
            except: pass
