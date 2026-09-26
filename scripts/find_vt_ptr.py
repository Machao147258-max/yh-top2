# -*- coding: utf-8 -*-
"""扫全库找指向 AES 虚表(0xdfaf6c0 附近)的 8 字节指针。"""
import struct
SO=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
d=open(SO,"rb").read()
def phdrs(p):
    eh=p[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
    o=[]
    for i in range(e_phnum):
        q=e_phoff+i*es
        if struct.unpack_from("<I",p,q)[0]!=1: continue
        fl=struct.unpack_from("<I",p,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",p,q+8)
        o.append((off,va,fs))
    return o
segs=phdrs(d)
def fo2va(fo):
    for off,va,fs in segs:
        if off<=fo<off+fs: return va+(fo-off)
    return None
def va2fo(va):
    for off,v,fs in segs:
        if v<=va<v+fs: return off+(va-v)
    return None

for target in [0xdfaf6c0,0xdfaf6c8,0xdfaf700]:
    pat=struct.pack("<Q",target)
    i=0; hits=[]
    while True:
        i=d.find(pat,i)
        if i<0: break
        hits.append(i); i+=1
    print(f"\n指向 0x{target:x} 的指针: {len(hits)} 处")
    for h in hits[:10]:
        print(f"   file=0x{h:x} vaddr=0x{(fo2va(h) or 0):x}")
