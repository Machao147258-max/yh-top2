# -*- coding: utf-8 -*-
"""找 IoStore 相关串(DirectoryIndex/IoStore/ContainerHeader)及其 adrp+add 引用代码。"""
import struct, numpy as np, capstone
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
segs=phdrs()
def va2fo(va):
    for off,v,fs,fl,ms in segs:
        if v<=va<v+fs: return off+(va-v)
    return None
# 找串地址
def find_str(s):
    out=[];i=0
    while True:
        i=raw.find(s,i)
        if i<0:break
        # 判断 i 是否在某段(且该段是 rodata/data): 算 vaddr
        va=None
        for off,v,fs,fl,ms in segs:
            if off<=i<off+fs: va=v+(i-off)
        out.append((i,va)); i+=1
    return out
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
def refs(T):
    page=T&~0xFFF; lo=T&0xFFF
    hits=np.where(is_adrp&(tgt==page))[0]; out=[]; seen=set()
    for i in hits:
        for d in (1,2,3):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                pc=int(pcs[j])
                if pc in seen: break
                seen.add(pc); out.append(pc); break
    return out
for s in (b"DirectoryIndex", b"IoStore", b"ContainerHeader", b"TocEntry", b"ContainerId"):
    print(f"\n##### 串 {s} #####")
    for fo,vaddr in find_str(s)[:3]:
        print(f"  @fo=0x{fo:x} va=0x{vaddr:x}")
        if vaddr:
            for pc in refs(vaddr)[:5]:
                print(f"    xref @0x{pc:x}")
print("\n完成")
