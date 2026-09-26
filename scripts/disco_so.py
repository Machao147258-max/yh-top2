# -*- coding: utf-8 -*-
"""通用 .so 反汇编: va->fo 用段映射。反汇编 libsecsdk 检测区 + libthemis 区。"""
import struct, capstone, os
from elftools.elf.elffile import ELFFile
W=r"C:\Users\20751\Desktop\异环"
def disco(name, va, ln):
    p=os.path.join(W,"unpacked","so",name)
    raw=open(p,"rb").read(); f=open(p,"rb"); elf=ELFFile(f)
    segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
    def v2f(va):
        for v,o,fs in segs:
            if v<=va<v+fs: return o+(va-v)
        return None
    md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    fo=v2f(va)
    print(f"\n===== {name} 0x{va:x} (fo 0x{fo:x}) =====")
    if fo is None: print("  无映射"); return
    for ins in md.disasm(raw[fo:fo+ln], va):
        t=""
        if ins.mnemonic in ("bl","b"):
            try: t=f"  -> 0x{int(ins.op_str.split('#')[-1],16):x}"
            except: pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
    f.close()
disco("libsecsdk.so", 0x7400, 0x1C0)
disco("libsecsdk.so", 0x7660, 0x160)
