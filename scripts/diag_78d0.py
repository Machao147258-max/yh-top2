# -*- coding: utf-8 -*-
import capstone
raw=open(r"D:\qwork\libsecsdk.so","rb").read()
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
def s(va,n=48):
    seg=raw[va:va+n].split(b"\x00")[0]
    return ''.join(chr(c) if 32<=c<127 else '.' for c in seg)
for va,ln,t in [(0x78d0,0x80,"内部函数0x78d0"),(0x92a4,0x40,"0x92a4")]:
    print(f"\n== {t} ==")
    adrp={}
    for ins in md.disasm(raw[va:va+ln],va):
        txt=f"{ins.mnemonic} {ins.op_str}"
        if ins.mnemonic=="adrp":
            try: adrp[ins.op_str.split(',')[0]]=int(ins.op_str.split('#')[1],16)
            except: pass
        if ins.mnemonic=="add":
            p=ins.op_str.split(',')
            if len(p)==3 and p[1].strip() in adrp:
                try: txt+=f"  ; '{s(adrp[p[1].strip()]+int(p[2].split('#')[1],16))}'"
                except: pass
        b=""
        if ins.mnemonic in("bl","b"):
            try:b=" ->0x%x"%int(ins.op_str.split('#')[-1],16)
            except:pass
        print(f"0x{ins.address:x}: {txt}{b}")
