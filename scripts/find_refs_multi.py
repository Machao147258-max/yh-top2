# -*- coding: utf-8 -*-
"""找 libUnreal 里 adrp+add 引用一组目标地址的代码位置。"""
import struct, numpy as np, capstone
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
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
adt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=((words>>10)&0xFFF); addn=((words>>5)&0x1F)
def refs(tgt):
    page=tgt&~0xFFF; lo=tgt&0xFFF; out=[]
    for i in np.where(is_adrp&(adt==page))[0]:
        for d in (1,2):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                out.append(int(pcs[i])); break
    return out
TGT={0xe295cd8:"keystore_arr",0xe295ce0:"keystore_cnt",0xe295b00:"keystore_once",
     0xe1ec250:"dec_fn",0xe28a0bc8:"reg1",0xe28a0bd8:"reg2",0xe35c880:"pakkey_once"}
for tgt,nm in TGT.items():
    r=refs(tgt); print(f"{nm} 0x{tgt:x}: {len(r)} 处 {[hex(x) for x in r[:16]]}")
