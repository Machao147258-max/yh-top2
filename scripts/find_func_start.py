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
# 向前找函数序言
tgt=0x9aae9e8
for a in range(tgt, tgt-0x1200, -4):
    try:
        ins=list(md.disasm(raw[v2f(a):v2f(a)+4], a))[0]
    except: continue
    if ins.mnemonic=="sub" and ins.op_str.startswith("sp, sp,") and a!=tgt:
        print(f"函数序言 @0x{a:x}: {ins.mnemonic} {ins.op_str}"); break
    if ins.mnemonic=="stp" and "x29, x30" in ins.op_str and "[sp, #-" in ins.op_str:
        print(f"函数序言(stp) @0x{a:x}: {ins.mnemonic} {ins.op_str}"); break
# 读描述符 0x9a93d08 附近
fo=v2f(0x9a93d08)
print(f"\n描述符 0x9a93d08 (fo {fo}): {raw[fo:fo+0x40].hex()}")
# 其内部指针
for off in range(0,0x20,8):
    val=struct.unpack_from("<Q",raw,fo+off)[0]
    print(f"  [+0x{off:x}] = 0x{val:x}")
# 若指向函数, 反汇编
def dis(va,ln,t=""):
    f2=v2f(va); print(f"\n== {t} 0x{va:x} ==")
    if f2 is None: print(" 无映射"); return
    for ins in md.disasm(raw[f2:f2+ln], va):
        tt=""
        if ins.mnemonic in("bl","b"):
            try: tt="  -> 0x%x"%int(ins.op_str.split('#')[-1],16)
            except:pass
        print(f"0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}{tt}")
p0=struct.unpack_from("<Q",raw,fo)[0]
if 0x1000<p0<0x10000000: dis(p0,0x80,"描述符[0]")
