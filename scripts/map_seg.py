# -*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
seg=open(r"C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin","rb").read()
f=open(r"D:\qwork\libsecsdk.so","rb"); elf=ELFFile(f); disk=f.read() if False else open(r"D:\qwork\libsecsdk.so","rb").read()
print("=== PT_LOAD 段 ===")
segs=[]
for s in elf.iter_segments():
    if s['p_type']=='PT_LOAD':
        print(f"  off=0x{s['p_offset']:x} vaddr=0x{s['p_vaddr']:x} filesz=0x{s['p_filesz']:x} memsz=0x{s['p_memsz']:x} flags={s['p_flags']}")
        segs.append((s['p_vaddr'],s['p_offset'],s['p_filesz']))
def rt2file(va):
    for v,o,sz in segs:
        if v<=va<v+sz: return o+(va-v)
    return None
i=seg.find(b"mutivmp")
while i>=0:
    fo=rt2file(i)
    print(f"\nruntime 0x{i:x} -> file {('0x%x'%fo) if fo is not None else None}")
    if fo is not None and fo<len(disk):
        print("  disk:", disk[fo-8:fo+48])
    print("  seg :", seg[i-8:i+48])
    i=seg.find(b"mutivmp", i+1)
# 统计运行时串表里有多少非磁盘可见串
import re
strs=set(re.findall(rb"[\x20-\x7e]{8,}", seg))
unseen=0
for s in strs:
    if disk.find(s)<0: unseen+=1
print(f"\n运行时镜像中 8+ 串: {len(strs)}, 其中磁盘不存在的: {unseen}")
