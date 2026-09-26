# -*- coding: utf-8 -*-
"""找引用 OodleLZ_Decompress 错误串的函数 (真正实现) + 找设置 [0xe63d578] 的代码。"""
import struct, numpy as np, capstone
SO=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
raw=open(SO,"rb").read()
import re
def phdrs():
    eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
    out=[]
    for i in range(e_phnum):
        q=e_phoff+i*es
        if struct.unpack_from("<I",raw,q)[0]!=1: continue
        fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
        out.append((off,va,fs,fl,ms))
    return out
segs=phdrs()
def va2fo(va):
    for off,v,fs,fl,ms in segs:
        if v<=va<v+fs: return off+(va-v)
    return None
# 串的 vaddr
for sv in (0xcd6a85,0xcd6c9c,0xcd73fa):
    fo=va2fo(sv); print(f"str 0x{sv:x} -> fo 0x{fo:x}" if fo else f"str 0x{sv:x} 无")
    if fo:
        frag=raw[fo:fo+40]
        print("   ", frag.split(b"\x00")[0][:40])
# 找引用这些串的代码
rx=[s for s in segs if s[3]&1][0]
off,va,fs,fl,ms=rx
words=np.frombuffer(raw[off:off+fs],dtype="<u4"); n=len(words)
idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4)
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
tgt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=((words>>10)&0xFFF); addn=((words>>5)&0x1F)
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
for T in (0xcd6a85,):
    page=T&~0xFFF; lo=T&0xFFF
    hits=np.where(is_adrp&(tgt==page))[0]; c=0
    print(f"\n=== 引用 0x{T:x} 的代码 ===")
    for i in hits:
        for d in (1,2,3):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                pc=int(pcs[j]); print(f"  函数内 @0x{pc:x}"); c+=1; break
    if c==0: print("  无")
