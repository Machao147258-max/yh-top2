# -*- coding: utf-8 -*-
"""在 libUnreal.so 里找 pak/utoc 魔数锚点，定位解析器。"""
import struct

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
data = open(SO, "rb").read()

def parse_phdrs(data):
    e_phoff=struct.unpack_from("<Q",data,0x20)[0]
    e_phnum=struct.unpack_from("<H",data,0x38)[0]
    e_phentsize=struct.unpack_from("<H",data,0x36)[0]
    segs=[]
    for i in range(e_phnum):
        o=e_phoff+i*e_phentsize
        if struct.unpack_from("<I",data,o)[0]!=1: continue
        fl=struct.unpack_from("<I",data,o+4)[0]
        off,va,_pa,fs,ms=struct.unpack_from("<5Q",data,o+8)
        segs.append((va,fs,off,fl))
    return segs
segs=parse_phdrs(data)
def v2seg(va):
    for va0,fs,off,fl in segs:
        if va0<=va<va0+fs: return (va0,fs,off,fl)
    return None

def scan(name, pat):
    i=0; hits=[]
    while True:
        i=data.find(pat,i)
        if i<0: break
        # file offset -> vaddr
        va=None
        for va0,fs,off,fl in segs:
            if off<=i<off+fs: va=va0+(i-off); break
        r="RX" if va is None else ("R" if va<0x24d974c else "?")
        hits.append((i,va))
        i+=1
    print(f"\n{name} ({pat.hex()}): {len(hits)} 处")
    for (fo,va) in hits[:12]:
        print(f"  file=0x{fo:x} vaddr={'?' if va is None else hex(va)}")

scan("pak magic 0x5A6F12E1 (LE)", struct.pack("<I",0x5A6F12E1))
scan("pak magic BE", struct.pack(">I",0x5A6F12E1))
scan("utoc magic", bytes.fromhex("2D3D3D2D2D3D3D2D2D3D3D2D2D3D3D2D"))
scan("'.utoc'", b".utoc")
scan("'pakchunk'", b"pakchunk")
scan("'IoStore'", b"IoStore")
scan("'FAES'", b"FAES")
scan("'EncryptionKey'", b"EncryptionKey")
