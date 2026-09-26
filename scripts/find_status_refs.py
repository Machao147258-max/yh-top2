# -*- coding: utf-8 -*-
"""libUnreal: 定位 '/proc/self/status' 串的 va + 谁引用它(反调试真身)。"""
import struct, numpy as np, capstone
SO=r"D:\qwork\libUnreal.so"
raw=open(SO,"rb").read()
eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
segs=[]
for i in range(e_phnum):
    q=e_phoff+i*es
    if struct.unpack_from("<I",raw,q)[0]!=1: continue
    fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
    segs.append((off,va,fs,ms,fl))
def f2v(fo):
    for o,v,fs,ms,fl in segs:
        if o<=fo<o+fs: return v+(fo-o)
    return None
def v2f(a):
    for o,v,fs,ms,fl in segs:
        if v<=a<v+fs: return o+(a-v)
# 找 "/proc/self/status" 的 fo, 转 va
found=[]
i=raw.find(b"/proc/self/status")
while i!=-1:
    va=f2v(i)
    if va: found.append((i,va))
    i=raw.find(b"/proc/self/status",i+1)
print("'/proc/self/status' 出现:", [(hex(f),hex(v)) for f,v in found])
# 反汇编引擎找 adrp+add 引用
rx=[s for s in segs if s[4]&1][0]; off,va,fs,ms,fl=rx
words=np.frombuffer(raw[off:off+fs],dtype="<u4"); n=len(words)
idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4).astype(np.int64)
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
adt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=((words>>10)&0xFFF); addn=((words>>5)&0x1F)
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
for fo,sva in found:
    refs=[]
    for i in np.where(is_adrp&(adt==(sva&~0xFFF)))[0]:
        for d in (1,2):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==(sva&0xFFF):
                refs.append(int(pcs[i])); break
    print(f"\n串 va=0x{sva:x} 引用 {len(refs)}: {[hex(r) for r in refs[:10]]}")
    for r in refs[:3]:
        f2=v2f(r-8)
        print(f"  --- 上下文 @0x{r:x} ---")
        for ins in md.disasm(raw[f2:f2+0x40], r-8):
            print(f"    0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}")
