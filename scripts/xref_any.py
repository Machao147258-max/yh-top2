# -*- coding: utf-8 -*-
"""通用: 扫机器码找 adrp+add 引用给定地址的代码(找虚表/函数指针装载点)。"""
import struct, numpy as np, capstone
SO=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
TARGETS=[0xABFA760,0xABFA8E0,0xABFA9A8,0xB587284,0xB587180,0x3ADA03C]
raw=open(SO,"rb").read()
def phdrs():
    import struct
    eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
    out=[]
    for i in range(e_phnum):
        q=e_phoff+i*es
        if struct.unpack_from("<I",raw,q)[0]!=1: continue
        fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
        out.append((off,va,fs,fl))
    return out
segs=phdrs()
rx=[s for s in segs if s[3]&1][0]
off,va,fs,fl=rx
words=np.frombuffer(raw[off:off+fs],dtype="<u4")
n=len(words); idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4).astype(np.int64)
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
tgt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=((words>>10)&0xFFF).astype(np.int64); addn=((words>>5)&0x1F).astype(np.int64)
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
print(f".text words={n} @0x{va:x}")
for T in TARGETS:
    page=T&~0xFFF; lo=T&0xFFF
    hits=np.where(is_adrp&(tgt==page))[0]
    print(f"\n=== ref 0x{T:x} ===   adrp命中 {len(hits)}")
    cnt=0
    for i in hits:
        for d in (1,2,3):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                pc=int(pcs[j]); fo=pc-va+off
                print(f"  @0x{pc:x}:")
                for ins in md.disasm(raw[fo-4:fo+8], pc-4):
                    print(f"     {ins.address:x}: {ins.mnemonic} {ins.op_str}")
                cnt+=1; break
        if cnt>=25: print("  ..."); break
    if cnt==0: print("  无")
