# -*- coding: utf-8 -*-
"""扫 libthemis/libsecsdk/libclient 里所有 svc #imm 指令 (直接系统调用)。
   svc 编码: (word & 0xFFE0001F) == 0xD4000001 """
import struct, glob, os
from elftools.elf.elffile import ELFFile
SD=r"C:\Users\20751\Desktop\异环\unpacked\so"
def scan(path):
    f=open(path,"rb"); elf=ELFFile(f)
    txt=elf.get_section_by_name('.text')
    if not txt: f.close(); return []
    base=txt['sh_addr']; d=txt.data()
    out=[]
    for off in range(0,len(d)-4,4):
        w=struct.unpack_from("<I",d,off)[0]
        if (w & 0xFFE0001F)==0xD4000001:
            imm=(w>>5)&0xFFFF
            out.append((base+off,imm))
    f.close(); return out
for so in ("libthemis.so","libsecsdk.so","libclient.so","libUnreal.so"):
    p=os.path.join(SD,so)
    if not os.path.exists(p): continue
    r=scan(p)
    print(f"\n=== {so}: {len(r)} 条 svc ===")
    for a,imm in r[:60]:
        print(f"  0x{a:x}: svc #{imm}")
    if len(r)>60: print(f"  ... 共 {len(r)}")
