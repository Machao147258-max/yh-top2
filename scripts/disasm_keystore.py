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
def dis(va,ln,title=""):
    fo=v2f(va); print(f"\n===== {title} 0x{va:x} (fo 0x{fo:x}) =====")
    for ins in md.disasm(raw[fo:fo+ln], va):
        t=""
        if ins.mnemonic in ("bl","b"):
            try: t="  -> 0x%x"%int(ins.op_str.split('#')[-1],16)
            except: pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
dis(0x26A26E0, 0x120, "keystore writer A")
dis(0x26B1420, 0x140, "keystore writer B")
# 静态初值: 0xe1ec250 / 0xe35c9c8 / 0xe28a0bc8 / 0xe28a0bd8
def rd64(va):
    fo=v2f(va); return struct.unpack_from("<Q",raw,fo)[0]
for va in (0xe1ec250,0xe35c9c8,0xe35c9d0,0xe28a0bc8,0xe28a0bd8,0xe63d578,0x26a1888):
    try: print(f"  [0x{va:x}] = 0x{rd64(va):x}")
    except Exception as e: print(f"  0x{va:x}: {e}")
