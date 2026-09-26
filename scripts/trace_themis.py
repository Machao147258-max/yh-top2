# -*- coding: utf-8 -*-
"""再追一层 + dump prctl PLT 桩字节。"""
import struct, capstone
from elftools.elf.elffile import ELFFile
SO=r"c:\Users\20751\Desktop\异环\unpacked\so\libthemis.so"
raw=open(SO,"rb").read()
eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
segs=[]
for i in range(e_phnum):
    q=e_phoff+i*es
    if struct.unpack_from("<I",raw,q)[0]!=1: continue
    fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
    segs.append((off,va,fs,ms,fl))
def v2f(a):
    for o,v,fs,ms,fl in segs:
        if v<=a<v+ms:
            if a<v+fs: return o+(a-v)
    return None
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
def start_of(tgt):
    for a in range(tgt,tgt-0x3000,-4):
        fo=v2f(a)
        if fo is None: continue
        try: ins=list(md.disasm(raw[fo:fo+4],a))[0]
        except: continue
        if (ins.mnemonic=="sub" and ins.op_str.startswith("sp, sp,")) or (ins.mnemonic=="stp" and "x29, x30" in ins.op_str and "[sp, #-" in ins.op_str):
            return a
    return None
rx=[s for s in segs if s[4]&1][0]; off,va,fs,ms,fl=rx
words=struct.unpack_from("<%dI"%(fs//4),raw,off); n=len(words)
def callers_of(tgt):
    out=[]
    for i in range(n):
        w=words[i]
        if (w&0xFC000000)==0x94000000:
            imm=w&0x03FFFFFF
            if imm>=(1<<25): imm-=(1<<26)
            if va+i*4+(imm<<2)==tgt: out.append(va+i*4)
    return out
for t in (0x7d248,):
    s=start_of(t)
    print(f"0x{t:x} 所属函数起点 0x{s:x}; 调用者 {[hex(c) for c in callers_of(s)]}")
# 再上溯
for t in (0x33440,0x334a0,0x33600,0x33670):
    print(f"JNI 0x{t:x} 起点的前 16 指令:")
    fo=v2f(t)
    for ins in list(md.disasm(raw[fo:fo+0x40],t))[:10]:
        b=""
        if ins.mnemonic in("bl","b"):
            try: b=" ->0x%x"%int(ins.op_str.split('#')[-1],16)
            except: pass
        print(f"   0x{ins.address:x}: {ins.mnemonic} {ins.op_str}{b}")
# prctl 桩 0xc8a60
fo=v2f(0xC8A60)
print(f"\nprctl 桩 0xc8a60 字节: {raw[fo:fo+16].hex()}")
for ins in md.disasm(raw[fo:fo+16],0xC8A60): print(f"   0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
