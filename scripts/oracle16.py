# -*- coding: utf-8 -*-
"""AES-128 版 oracle：16 字节候选 + ECB，解密 pak 索引，SHA1 比对 + ASCII 比例。"""
import struct, numpy as np, hashlib
from Crypto.Cipher import AES

SO  = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
PAK = r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
IOFF, ISZ = 0x2f41376, 0x11320
STORED = bytes.fromhex("eda462f54e6b194fa3474b5791dfab404b95ca7b")
with open(PAK,"rb") as f:
    f.seek(IOFF); enc=f.read(ISZ)

def parse_phdrs(p):
    f=open(p,"rb"); eh=f.read(0x40)
    e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
    f.seek(e_phoff); ph=f.read(es*e_phnum); out=[]
    for i in range(e_phnum):
        o=i*es
        if struct.unpack_from("<I",ph,o)[0]!=1: continue
        fl=struct.unpack_from("<I",ph,o+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",ph,o+8)
        out.append(dict(off=off,vaddr=va,filesz=fs,flags=fl))
    return out

segs=parse_phdrs(SO); data=open(SO,"rb").read()
rx=[s for s in segs if s["flags"]&1][0]
words=np.frombuffer(data[rx["off"]:rx["off"]+rx["filesz"]],dtype="<u4")
n=len(words); idx=np.arange(n,dtype=np.int64); pcs=(rx["vaddr"]+idx*4).astype(np.int64)
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
tgt=(pcs&~0xFFF)+imm; rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=(words>>10)&0xFFF; addn=(words>>5)&0x1F
targets=set()
for i in np.where(is_adrp)[0]:
    for d in (1,2):
        j=i+d
        if j<n and is_add[j] and rd[i]==addn[j]:
            targets.add(int(tgt[i])+int(addi[j]))

# 非执行可读段
segs2=[s for s in segs if not(s["flags"]&1) and (s["flags"]&4)]
def readN(va,N):
    for s in segs2:
        if s["vaddr"]<=va and va+N<=s["vaddr"]+s["filesz"]:
            fo=s["off"]+(va-s["vaddr"]); return data[fo:fo+N]
    return None

cands={}
for va in targets:
    b=readN(va,16)
    if b and len(b)==16 and b.count(0)<=2:
        cands[b]=va
print(f"16B 候选: {len(cands)}")

hit=None; res=[]
for k,va in cands.items():
    for mode in ("ecb","cbc"):
        try:
            pt = AES.new(k,AES.MODE_ECB).decrypt(enc) if mode=="ecb" else AES.new(k,AES.MODE_CBC,b"\0"*16).decrypt(enc)
        except Exception: continue
        if hashlib.sha1(pt).digest()==STORED:
            hit=(k,va,mode); print(f"*** SHA1 命中! key@{va:#x} {mode} {k.hex()}"); break
        pr=sum(1 for c in pt[:8192] if 0x20<=c<0x7f)/8192
        res.append((pr,mode,va,pt[:32]))
    if hit: break
if not hit:
    print("SHA1 未命中；ASCII 比例 Top8:")
    res.sort(key=lambda x:-x[0])
    for pr,mode,va,pv in res[:8]:
        print(f"  {pr:.3f} {mode} key@{va:#x} {pv!r}")
