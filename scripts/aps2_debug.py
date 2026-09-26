# -*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libUnreal.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
dyn=elf.get_section_by_name('.dynamic'); DT={t.entry.d_tag:t.entry.d_val for t in dyn.iter_tags()}
off=DT['DT_ANDROID_RELA']; sz=DT['DT_ANDROID_RELASZ']
blob=raw[off:off+sz]
print("blob len", len(blob))
print("head:", blob[:48].hex())
# 手动 uleb
def uleb(d,p):
    r=0;s=0
    while True:
        b=d[p];p+=1;r|=(b&0x7f)<<s;s+=7
        if not (b&0x80):break
    return r,p
p=4
cnt,p=uleb(blob,p)
print(f"after magic, count={cnt}, next byte pos={p} byte=0x{blob[p]:02x}")
print("next 24 bytes:", blob[p:p+24].hex())
