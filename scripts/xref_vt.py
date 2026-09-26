# -*- coding: utf-8 -*-
"""从机器码找引用 AES 虚表(0xdfaf6c0 页)的代码。"""
import struct, numpy as np, capstone
SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
TARGETS=[0xdfaf6c0, 0xdfaf6c8, 0xdfaf6e8, 0xdfaf6f0]
def phdrs(p):
    f=open(p,"rb"); eh=f.read(0x40)
    e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
    f.seek(e_phoff); ph=f.read(es*e_phnum); o=[]
    for i in range(e_phnum):
        q=i*es
        if struct.unpack_from("<I",ph,q)[0]!=1: continue
        fl=struct.unpack_from("<I",ph,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",ph,q+8)
        o.append(dict(off=off,vaddr=va,filesz=fs,flags=fl))
    return o
segs=phdrs(SO); data=open(SO,"rb").read()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
rx=[s for s in segs if s["flags"]&1][0]
words=np.frombuffer(data[rx["off"]:rx["off"]+rx["filesz"]],dtype="<u4")
n=len(words); idx=np.arange(n,dtype=np.int64); pcs=(rx["vaddr"]+idx*4).astype(np.int64)
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
tgt=(pcs&~0xFFF)+imm; rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=(words>>10)&0xFFF; addn=(words>>5)&0x1F
for T in TARGETS:
    page=T&~0xFFF; lo=T&0xFFF
    hits=np.where(is_adrp&(tgt==page))[0]
    print(f"\n=== xref 0x{T:x} ===")
    found=0
    for i in hits:
        for d in (1,2,3):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                pc=int(pcs[j]); print(f"  <- 0x{pc:x}")
                o=pc-rx["vaddr"]+rx["off"]
                for ins in md.disasm(data[o-8:o+16], pc-8):
                    print(f"      {ins.address:x}: {ins.mnemonic} {ins.op_str}")
                found+=1; break
    if not found: print("  无（可能被 ptr 二次引用）")
