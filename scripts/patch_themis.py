# -*- coding: utf-8 -*-
"""针对 libthemis: patch prctl 的 PLT 桩 -> mov w0,#0; ret (反调试失效)。
所有走该桩的 prctl 调用全部变成返回0。产出 libthemis_patched.so。"""
import struct, shutil
from elftools.elf.elffile import ELFFile
SRC=r"c:\Users\20751\Desktop\异环\unpacked\so\libthemis.so"
DST=r"D:\qwork\libthemis_patched.so"
PRCTL_STUB=0xC8A60
# mov w0,#0 ; ret ; nop ; nop
PATCH=bytes.fromhex("00008052") + bytes.fromhex("c0035fd6") + bytes.fromhex("1f2003d5") + bytes.fromhex("1f2003d5")
data=bytearray(open(SRC,"rb").read())
f=open(SRC,"rb"); elf=ELFFile(f)
segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
def v2f(a):
    for v,o,fs in segs:
        if v<=a<v+fs: return o+(a-v)
    return None
fo=v2f(PRCTL_STUB)
print(f"prctl 桩 va=0x{PRCTL_STUB:x} fo=0x{fo:x}")
print("原: ", data[fo:fo+16].hex())
data[fo:fo+16]=PATCH
print("新: ", data[fo:fo+16].hex())
open(DST,"wb").write(bytes(data))
print("已写:", DST)
# 反汇编确认
import capstone
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
for ins in md.disasm(bytes(data[fo:fo+16]), PRCTL_STUB):
    print("  ", hex(ins.address), ins.mnemonic, ins.op_str)
f.close()
