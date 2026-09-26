# -*- coding: utf-8 -*-
"""扫引用关键全局 0xe35c64c(key存储) 的代码 + 找 'Oodle' GUID 在 .rodata 的出现。"""
import struct, numpy as np, capstone
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
BD=0x4000
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
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
def refs(T, ctx=6):
    page=T&~0xFFF; lo=T&0xFFF
    hits=np.where(is_adrp&(tgt==page))[0]; out=[]; seen=set()
    for i in hits:
        for d in (1,2,3):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                pc=int(pcs[j])
                if pc in seen: break
                seen.add(pc)
                fo2=pc-va+off
                lines=[]
                for ins in md.disasm(raw[fo2-ctx*4:fo2+4*4], pc-ctx*4):
                    lines.append(f"    {ins.address:x}: {ins.mnemonic} {ins.op_str}")
                out.append("\n".join(lines)); break
    return out
for T in (0xe35c64c, 0xe35c650, 0xe35c658):
    r=refs(T)
    print(f"\n===== ref 0x{T:x} ({len(r)} 处) =====")
    for x in r[:12]: print(x)
# .rodata 里找 'Oodle' GUID 的字节
g=b"Oodle\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
i=0; hits=[]
while True:
    i=raw.find(g,i)
    if i<0: break
    hits.append(i); i+=1
print(f"\n'Oodle'+11nul 出现: {[hex(h) for h in hits]}")
# 也找 'Oodle' 短串
i=0; h2=[]
while True:
    i=raw.find(b"Oodle",i)
    if i<0: break
    h2.append(i); i+=1
print(f"'Oodle' 子串出现 {len(h2)} 处(前20): {[hex(x) for x in h2[:20]]}")
