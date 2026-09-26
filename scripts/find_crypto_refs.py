# -*- coding: utf-8 -*-
"""找 libUnreal 里引用 crypto 全局(0xe1ec250/0xe35c9c8/0xe35c9d0/0xe63d578)的代码 + 附近是否 store。"""
import struct, numpy as np, capstone
SO=r"D:\qwork\libUnreal.so"
raw=open(SO,"rb").read()
# PT_LOAD 段
eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
segs=[]
for i in range(e_phnum):
    q=e_phoff+i*es
    if struct.unpack_from("<I",raw,q)[0]!=1: continue
    fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
    segs.append((off,va,fs,fl))
rx=[s for s in segs if s[3]&1][0]
off,va,fs,fl=rx
words=np.frombuffer(raw[off:off+fs],dtype="<u4"); n=len(words)
idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4).astype(np.int64)
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
adt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=((words>>10)&0xFFF); addn=((words>>5)&0x1F)
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
TARGETS={0xe1ec250:"dec_fn",0xe35c9c8:"crypto_arr",0xe35c9d0:"crypto_cnt",0xe63d578:"Oodle_fn"}
def v2f(a):
    for o,v,sz,f in segs:
        if v<=a<v+sz: return o+(a-v)
for tgt,nm in TARGETS.items():
    page=tgt&~0xFFF; lo=tgt&0xFFF
    hits=np.where(is_adrp&(adt==page)&(rd!=16))[0]
    print(f"\n===== {nm} 0x{tgt:x} (页 0x{page:x}) =====")
    found=[]
    for i in hits:
        for d in (1,2):
            j=i+d
            if j<n and is_add[j] and rd[i]==addn[j] and int(addi[j])==lo:
                found.append(int(pcs[i])); break
    print(f"  adrp+add 引用 {len(found)} 处: {[hex(x) for x in found[:20]]}")
    for a in found[:6]:
        fo=v2f(a-4)
        print(f"  --- 上下文 @0x{a:x} ---")
        for ins in md.disasm(raw[fo:fo+0x30], a-4):
            print(f"    0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}")
