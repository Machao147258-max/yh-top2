# -*- coding: utf-8 -*-
"""诊断 libsecsdk 崩溃点 0xb674: 反汇编周围 + 看它往哪写。"""
import capstone
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
raw=open(SO,"rb").read(); f=open(SO,"rb"); elf=ELFFile(f)
segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
def v2f(a):
    for v,o,fs in segs:
        if v<=a<v+fs: return o+(a-v)
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
print("段:", [(hex(v),hex(o),hex(fs)) for v,o,fs in segs])
for va in (0xB600,):
    fo=v2f(va)
    for ins in md.disasm(raw[fo:fo+0xe0], va):
        t=""
        if ins.mnemonic in("bl","b"):
            try:t=" ->0x%x"%int(ins.op_str.split('#')[-1],16)
            except:pass
        mark=" <<<崩溃点" if ins.address==0xB674 else ""
        print(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}{t}{mark}")
f.close()
