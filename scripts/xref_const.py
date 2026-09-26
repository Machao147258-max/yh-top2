# -*- coding: utf-8 -*-
"""通用：xref 一个 .rodata 常量地址（找 adrp+add/ldr 引用它的代码）。"""
import struct, numpy as np, capstone, sys

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
TARGETS = [0x945ff0]   # pak magic 常量

def parse_phdrs(path):
    f=open(path,"rb"); eh=f.read(0x40)
    e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]
    e_phentsize=struct.unpack_from("<H",eh,0x36)[0]
    f.seek(e_phoff); ph=f.read(e_phentsize*e_phnum); segs=[]
    for i in range(e_phnum):
        o=i*e_phentsize
        if struct.unpack_from("<I",ph,o)[0]!=1: continue
        fl=struct.unpack_from("<I",ph,o+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",ph,o+8)
        segs.append(dict(off=off,vaddr=va,filesz=fs,flags=fl))
    return segs

segs=parse_phdrs(SO); data=open(SO,"rb").read()
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
    print(f"\n=== xref 0x{T:x} (page 0x{page:x} lo 0x{lo:x}) ===")
    hits=np.where(is_adrp&(tgt==page))[0]
    found=0
    for i in hits:
        for d in (1,2,3):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                pc=int(pcs[j])
                print(f"  命中 @ 0x{pc:x}")
                o=pc-rx["vaddr"]+rx["off"]
                for ins in md.disasm(data[o-8:o+20], pc-8):
                    print(f"      0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
                found+=1
                break
    if not found:
        print("  （无精确 adrp+add 引用）")
