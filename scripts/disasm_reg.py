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
    fo=v2f(va); print(f"\n===== {title} 0x{va:x} (fo {fo}) =====")
    if fo is None: print("  !无映射"); return
    for ins in md.disasm(raw[fo:fo+ln], va):
        t=""
        if ins.mnemonic in ("bl","b"):
            try: t="  -> 0x%x"%int(ins.op_str.split('#')[-1],16)
            except: pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{t}")
dis(0x9aae9a0, 0xa0, "注册触发器调用者")
dis(0x3ad4c40, 0x120, "keystore 另一用户")
