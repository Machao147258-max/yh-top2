# -*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libUnreal.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
dyn=elf.get_section_by_name('.dynamic')
for t in dyn.iter_tags():
    tn=t.entry.d_tag
    if 'ANDROID' in tn or 'RELA' in tn or 'RELR' in tn or tn in ('DT_REL','DT_RELA','DT_JMPREL'):
        print(f"  {tn} = {t.entry.d_val}")
# 搜 APS2
i=0; hits=[]
while True:
    i=raw.find(b"APS2",i)
    if i<0: break
    hits.append(i); i+=1
print("APS2 出现位置:", [hex(x) for x in hits])
# 也搜 RELR 那种 magic? RELR 没 magic
# dump 几个 DT 指向处
