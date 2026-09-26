# -*- coding: utf-8 -*-
"""看 libUnreal 0x24e7968 那个 /proc/self/status 函数 引用的字符串 + 搜 TracerPid。"""
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
def s_at(va,n=48):
    fo=v2f(va)
    if fo is None: return "<无>"
    seg=raw[fo:fo+n].split(b"\x00")[0]
    return ''.join(chr(c) if 32<=c<127 else '.' for c in seg)
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
# 反汇编 0x24e7920..0x24e7a40, 收集 adrp+add
print("=== 反汇编 0x24e7920 区, 带 adrp+add 串 ===")
adrp_reg={}
for ins in md.disasm(raw[v2f(0x24e7920):v2f(0x24e7920)+0x130], 0x24e7920):
    txt=f"{ins.mnemonic} {ins.op_str}"
    if ins.mnemonic=="adrp":
        try:
            reg=ins.op_str.split(",")[0].strip(); imm=int(ins.op_str.split("#")[1],16)
            adrp_reg[reg]=imm
        except: pass
    if ins.mnemonic=="add" and "," in ins.op_str:
        p=ins.op_str.split(",")
        if len(p)==3 and p[1].strip() in adrp_reg:
            try:
                va=adrp_reg[p[1].strip()]+int(p[2].split("#")[1],16)
                txt+=f"   ; =0x{va:x} '{s_at(va)}'"
            except: pass
    b=""
    if ins.mnemonic in ("bl","b"):
        try: b="  ->0x%x"%int(ins.op_str.split('#')[-1],16)
        except: pass
    print(f"0x{ins.address:x}: {txt}{b}")
print("\n全库搜 'TracerPid':", raw.find(b"TracerPid"))
print("全库搜 'VmRSS':", raw.find(b"VmRSS"), " 'VmSize':", raw.find(b"VmSize"), " 'Threads':", raw.find(b"Threads"))
