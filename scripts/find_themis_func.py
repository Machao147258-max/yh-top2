# -*- coding: utf-8 -*-
"""libthemis: 找 0x71ef8 所在函数起点 + 谁调用它 + prctl 桩所在 .plt。"""
import struct, capstone
import os
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
# 向前找序言
tgt=0x71EF8
start=None
for a in range(tgt,tgt-0x3000,-4):
    fo=v2f(a)
    if fo is None: continue
    try: ins=list(md.disasm(raw[fo:fo+4],a))[0]
    except: continue
    if ins.mnemonic=="sub" and ins.op_str.startswith("sp, sp,"):
        start=a; print(f"函数序言 @0x{a:x}: {ins.mnemonic} {ins.op_str}"); break
    if ins.mnemonic=="stp" and "x29, x30" in ins.op_str and "[sp, #-" in ins.op_str:
        start=a; print(f"函数序言(stp) @0x{a:x}: {ins.mnemonic} {ins.op_str}"); break
if start:
    # 找 bl 调用此函数的点
    rx=[s for s in segs if s[4]&1][0]; off,va,fs,ms,fl=rx
    words=struct.unpack_from("<%dI"%(fs//4),raw,off); n=len(words)
    callers=[]
    for i in range(n):
        w=words[i]
        if (w&0xFC000000)==0x94000000:
            imm=w&0x03FFFFFF
            if imm>=(1<<25): imm-=(1<<26)
            tgt2=va+i*4+(imm<<2)
            if tgt2==start: callers.append(va+i*4)
    print(f"函数 @0x{start:x} 的 bl 调用者 {len(callers)}: {[hex(c) for c in callers[:20]]}")
# 导出表: 谁是 ThemisLite 方法
from elftools.elf.elffile import ELFFile
f=open(SO,"rb"); elf=ELFFile(f)
print("\n导出(JNI):")
for s in elf.get_section_by_name('.dynsym').iter_symbols():
    if s.name and s['st_shndx']!='SHN_UNDEF' and ("Java_" in s.name or s.name=="JNI_OnLoad"):
        print(f"  0x{s['st_value']:x} {s.name}")
f.close()
