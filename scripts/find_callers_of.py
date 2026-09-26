# -*- coding: utf-8 -*-
"""找 libUnreal 里 bl 到指定函数地址的所有调用点。"""
import struct, numpy as np
raw=open(r"D:\qwork\libUnreal.so","rb").read()
eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
segs=[]
for i in range(e_phnum):
    q=e_phoff+i*es
    if struct.unpack_from("<I",raw,q)[0]!=1: continue
    fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
    segs.append((off,va,fs,fl))
rx=[s for s in segs if s[3]&1][0]; off,va,fs,fl=rx
words=np.frombuffer(raw[off:off+fs],dtype="<u4"); n=len(words)
idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4).astype(np.int64)
is_bl=(words&0xFC000000)==0x94000000
imm26=(words&0x03FFFFFF).astype(np.int64); imm26=np.where(imm26>=(1<<25),imm26-(1<<26),imm26)
btgt=(pcs+(imm26<<2)).astype(np.int64)
def callers(tgt):
    out=[]
    for i in np.where(is_bl&(btgt==tgt))[0]:
        out.append(int(pcs[i]))
    return out
for tgt,nm in [(0x26a26e8,"注册 writerA"),(0x26b1420,"取key writerB"),(0x26a1888,"keystore访问器")]:
    c=callers(tgt); print(f"{nm} 0x{tgt:x}: {len(c)} 调用点 {[hex(x) for x in sorted(c)[:30]]}")
