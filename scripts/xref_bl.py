# -*- coding: utf-8 -*-
"""扫 bl 指令, 找调用指定目标的代码。"""
import struct, numpy as np
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
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
imm26=(words&0x03FFFFFF).astype(np.int64)
imm26=np.where(imm26>=(1<<25), imm26-(1<<26), imm26)
btgt=(pcs+(imm26<<2)).astype(np.int64)
for T in (0x3ADA03C, 0x3AD9050, 0x3AC7CA8, 0x264DA0C):
    hits=np.where(is_bl&(btgt==T))[0]
    print(f"\n调用 0x{T:x}: {len(hits)} 处")
    for i in hits[:12]:
        print(f"   bl @0x{int(pcs[i])-4:x}")
