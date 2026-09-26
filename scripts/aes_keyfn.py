# -*- coding: utf-8 -*-
"""反汇编 0x267F800..0x267FC00 找 AES key setup 入口, 并扫 bl 调用者。"""
import struct, numpy as np, capstone
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BD=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
print("=== 反汇编 0x267FA00..0x267FC40 ===")
for ins in md.disasm(raw[0x267FA00-BD:0x267FC40-BD], 0x267FA00):
    t=""
    if ins.mnemonic=="bl" and ins.op_str.startswith("#"):
        try: t=f" -> 0x{int(ins.op_str[1:],16):x}"
        except: pass
    print(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}{t}")
# 扫 bl 到 0x267FB74
def phdrs():
    eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
    out=[]
    for i in range(e_phnum):
        q=e_phoff+i*es
        if struct.unpack_from("<I",raw,q)[0]!=1: continue
        fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
        out.append((off,va,fs,fl,ms))
    return out
segs=phdrs(); rx=[s for s in segs if s[3]&1][0]
off,va,fs,fl,ms=rx
words=np.frombuffer(raw[off:off+fs],dtype="<u4"); n=len(words)
idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4).astype(np.int64)
is_bl=(words&0xFC000000)==0x94000000
imm26=(words&0x03FFFFFF).astype(np.int64); imm26=np.where(imm26>=(1<<25),imm26-(1<<26),imm26)
btgt=(pcs+(imm26<<2)).astype(np.int64)
for T in (0x267FB74,0x267FC98,0x267FC00,0x267F9C0):
    h=np.where(is_bl&(btgt==T))[0]
    print(f"bl -> 0x{T:x}: {len(h)} 处: {[hex(int(pcs[i])-4) for i in h[:10]]}")
