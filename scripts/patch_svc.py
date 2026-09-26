# -*- coding: utf-8 -*-
"""patch libthemis 所有 svc#0 -> nop (0xD503201F), 输出 libthemis_nosvc.so。
   svc#0 = 0xD4000001; (word&0xFFE0001F)==0xD4000001。"""
import struct, shutil
SRC=r"D:\qwork\libthemis.so"; DST=r"D:\qwork\libthemis_nosvc.so"
NOP=0xD503201F
data=bytearray(open(SRC,"rb").read())
from elftools.elf.elffile import ELFFile
elf=ELFFile(open(SRC,"rb"))
txt=elf.get_section_by_name('.text'); tbase=txt['sh_addr']; soff=txt['sh_offset']; ssize=txt['sh_size']
cnt=0; sites=[]
for i in range(0,ssize-4,4):
    w=struct.unpack_from("<I",data,soff+i)[0]
    if (w & 0xFFE0001F)==0xD4000001:
        struct.pack_into("<I",data,soff+i,NOP); cnt+=1; sites.append(tbase+i)
open(DST,"wb").write(data)
print(f"patch {cnt} 条 svc -> nop")
print("前10 site:", [hex(x) for x in sites[:10]])
# 验证
d2=open(DST,"rb").read()
bad=0
for i in range(0,ssize-4,4):
    if (struct.unpack_from("<I",d2,soff+i)[0] & 0xFFE0001F)==0xD4000001: bad+=1
print(f"剩余 svc: {bad}  (应为0)")
print("输出:", DST)
