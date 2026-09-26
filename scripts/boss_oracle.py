# -*- coding: utf-8 -*-
"""Boss: 用 retoc(正确oracle) 并行复跑 libUnreal 的 adrp+add 32B 常量候选。"""
import struct, subprocess, os, numpy as np
from concurrent.futures import ThreadPoolExecutor
W=r"C:\Users\20751\Desktop\异环"
SO=os.path.join(W,"unpacked","so","libUnreal.so")
RETOC=os.path.join(W,"tools","retoc.exe")
UTOC=os.path.join(W,"unpacked","io","pakchunk0-Android_ASTC.utoc")

def phdrs(raw):
    eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
    out=[]
    for i in range(e_phnum):
        q=e_phoff+i*es
        if struct.unpack_from("<I",raw,q)[0]!=1: continue
        fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
        out.append((off,va,fs,fl))
    return out
raw=open(SO,"rb").read()
segs=phdrs(raw)
rx=[s for s in segs if s[3]&1][0]
off,va,fs,fl=rx
words=np.frombuffer(raw[off:off+fs],dtype="<u4"); n=len(words)
idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4)
is_adrp=(words&0x9F000000)==0x90000000
immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
tgt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
is_add=(words&0xFF800000)==0x91000000; addi=((words>>10)&0xFFF); addn=((words>>5)&0x1F)
targets=set()
ad=np.where(is_adrp)[0]
for i in ad:
    for d in (1,2):
        j=i+d
        if j<n and is_add[j] and rd[i]==addn[j]:
            targets.add(int(tgt[i])+int(addi[j]))
print(f"adrp+add 目标 {len(targets)}")
# 只保留落在 R/RW 段、能读 32B 的
RR=[]
for (o,v,sz,f) in segs:
    if sz and (f&4): RR.append((o,v,sz))
def readX(va,L):
    for (o,v,sz) in RR:
        if v<=va and va+L<=v+sz:
            fo=o+(va-v); return raw[fo:fo+L]
    return None
keys=set()
for va in targets:
    b=readX(va,32)
    if b and b.count(0)<=8:
        keys.add(b[:32])
print(f"去重后 32B 候选 {len(keys)}")
keys=sorted(keys)
# 生成待测 key 列表(bin32 两种长度)
jobs=[]
for b in keys:
    jobs.append(b.hex())          # 32B
    jobs.append(b[:16].hex())     # 16B
print(f"待测 key {len(jobs)}")

def test(k):
    try:
        r=subprocess.run([RETOC,"-a",k,"info",UTOC],capture_output=True,timeout=15)
        if r.returncode==0: return k
    except Exception: pass
    return None

found=[]
with ThreadPoolExecutor(max_workers=12) as ex:
    for i,res in enumerate(ex.map(test, jobs, chunksize=64)):
        if res: print("★命中:",res); found.append(res)
        if i%5000==0: print(f"  ...{i}/{len(jobs)}")
print("命中:", found if found else "无")
