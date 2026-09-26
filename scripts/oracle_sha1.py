# -*- coding: utf-8 -*-
"""精确 oracle：SHA1(AES_dec(cand, enc)) == IndexHash  ->  命中即真 key。"""
import struct, numpy as np, hashlib
from Crypto.Cipher import AES

SO  = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
PAK = r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
IOFF, ISZ = 0x2f41376, 0x11320
STORED = bytes.fromhex("eda462f54e6b194fa3474b5791dfab404b95ca7b")

with open(PAK, "rb") as f:
    f.seek(IOFF); enc = f.read(ISZ)

def parse_phdrs(path):
    f = open(path, "rb"); eh = f.read(0x40)
    e_phoff = struct.unpack_from("<Q", eh, 0x20)[0]
    e_phnum = struct.unpack_from("<H", eh, 0x38)[0]
    e_phentsize = struct.unpack_from("<H", eh, 0x36)[0]
    f.seek(e_phoff); ph = f.read(e_phentsize*e_phnum)
    segs=[]
    for i in range(e_phnum):
        o=i*e_phentsize
        if struct.unpack_from("<I",ph,o)[0]!=1: continue
        fl=struct.unpack_from("<I",ph,o+4)[0]
        off,va,_pa,fs,ms=struct.unpack_from("<5Q",ph,o+8)
        segs.append(dict(off=off,vaddr=va,filesz=fs,flags=fl))
    return segs

def collect(so):
    segs=parse_phdrs(so); data=open(so,"rb").read()
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
    segs2=[s for s in segs if not(s["flags"]&1) and (s["flags"]&4)]
    out={}
    for va in targets:
        for s in segs2:
            if s["vaddr"]<=va and va+32<=s["vaddr"]+s["filesz"]:
                b=data[s["off"]+(va-s["vaddr"]):s["off"]+(va-s["vaddr"])+32]
                out[b]=va; break
    return out

def main():
    cands=collect(SO)
    print(f"候选: {len(cands)}")
    hit=None
    for k,va in cands.items():
        for mode in ("ecb","cbc"):
            try:
                pt = AES.new(k,AES.MODE_ECB).decrypt(enc) if mode=="ecb" \
                     else AES.new(k,AES.MODE_CBC,b"\0"*16).decrypt(enc)
            except Exception:
                continue
            if hashlib.sha1(pt).digest()==STORED:
                hit=(k,va,mode); break
        if hit: break
    if hit:
        k,va,mode=hit
        print(f"\n*** 命中! key@{va:#x} mode={mode}")
        print("KEY =", k.hex())
    else:
        print("\n未命中（候选集里没有真 key）")

if __name__=="__main__":
    main()
