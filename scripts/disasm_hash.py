# -*- coding: utf-8 -*-
"""反汇编 sub_26E236C(hash), sub_3AC7E14; 扫引用 0xe35c9c8 / 0xe35c880 的代码。"""
import capstone, struct, numpy as np
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BD=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
def dis(va, ln, title):
    fo=va-BD
    print(f"\n===== {title} 0x{va:x} =====")
    for ins in md.disasm(raw[fo:fo+ln], va):
        t=""
        if ins.mnemonic=="bl" and ins.op_str.startswith("#"):
            try: t=f"  -> 0x{int(ins.op_str[1:],16):x}"
            except: pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
dis(0x26E236C, 0x100, "hash sub_26E236C")
dis(0x3AC7E14, 0x120, "sub_3AC7E14")

# 扫引用 0xe35c9c8 / 0xe35c880
def phdrs():
    eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
    out=[]
    for i in range(e_phnum):
        q=e_phoff+i*es
        if struct.unpack_from("<I",raw,q)[0]!=1: continue
        fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
        out.append((off,va,fs,fl))
    return out
segs=phdrs(); rx=[s for s in segs if s[3]&1][0]
off,va,fs,fl=rx
words=np.frombuffer(raw[off:off+fs],dtype="<u4"); n=len(words)
idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4)
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
tgt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=((words>>10)&0xFFF); addn=((words>>5)&0x1F)
for T in (0xe35c9c8, 0xe35c880):
    page=T&~0xFFF; lo=T&0xFFF
    hits=np.where(is_adrp&(tgt==page))[0]; c=0
    print(f"\n=== ref 0x{T:x} (adrp命中{len(hits)}) ===")
    for i in hits:
        for d in (1,2,3):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                fo2=int(pcs[j])-va+off
                print(f"  @0x{int(pcs[j]):x}:")
                for ins in md.disasm(raw[fo2-4:fo2+8], int(pcs[j])-4):
                    print(f"     {ins.address:x}: {ins.mnemonic} {ins.op_str}")
                c+=1; break
        if c>=15: print("  ..."); break
    if c==0: print("  无")
