# -*- coding: utf-8 -*-
import struct, capstone
raw=open(r"D:\qwork\libUnreal.so","rb").read()
eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
segs=[]
for i in range(e_phnum):
    q=e_phoff+i*es
    if struct.unpack_from("<I",raw,q)[0]!=1: continue
    off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8); segs.append((va,off,fs))
def v2f(a):
    for v,o,sz in segs:
        if v<=a<v+sz: return o+(a-v)
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
def dis(va,ln,t=""):
    f2=v2f(va); print(f"\n== {t} 0x{va:x} ==")
    for ins in md.disasm(raw[f2:f2+ln], va):
        tt=""
        if ins.mnemonic in("bl","b"):
            try: tt="  -> 0x%x"%int(ins.op_str.split('#')[-1],16)
            except:pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{tt}")
dis(0x9a93d08, 0x100, "key-provider 回调?")
# 也看 registrar 后的启动函数 0x9aae9e8 起点: 找 0x9aae900 区
dis(0x9aae8e0, 0xc0, "启动函数尾部区")
