# -*- coding: utf-8 -*-
"""静态提取 libtprt 解密器的 (addr->K), 然后解出字符串。"""
import capstone, re, struct
from elftools.elf.elffile import ELFFile
P=r'D:\qwork\libtprt.so'
raw=open(P,'rb').read()
elf=ELFFile(open(P,'rb'))
txt=elf.get_section_by_name('.text')
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(txt.data(), txt['sh_addr']))
xreg={}; wreg={}; K={}; recs={}
def w32(v): return v & 0xffffffff
for x in ins:
    m=x.mnemonic; op=x.op_str
    if m=='adrp':
        mm=re.match(r'(x\d+), #(0x[0-9a-f]+)', op)
        if mm: xreg[mm.group(1)]=int(mm.group(2),16)
    elif m=='add':
        mm=re.match(r'(x\d+), (x\d+), #(0x[0-9a-f]+)', op)
        if mm and mm.group(2) in xreg:
            xreg[mm.group(1)]=(xreg[mm.group(2)]+int(mm.group(3),16))&0xffffffffffffffff
        mm2=re.match(r'(w\d+), (w\d+), #(\d+)', op)
        if mm2 and mm2.group(2) in wreg: wreg[mm2.group(1)]=w32(wreg[mm2.group(2)]+int(mm2.group(3)))
    elif m in ('mov','movz'):
        mm=re.match(r'(w\d+), #(-?0x[0-9a-f]+|-?\d+)', op)
        if mm: wreg[mm.group(1)]=w32(int(mm.group(2),0))
    elif m=='eor':
        mm=re.match(r'(w\d+), (w\d+), #(0x[0-9a-f]+|\d+)', op)
        if mm: K[mm.group(1)]=int(mm.group(3),0)&0xff
        else:
            mm2=re.match(r'(w\d+), (w\d+), (w\d+)', op)
            if mm2 and mm2.group(3) in wreg: K[mm2.group(1)]=wreg[mm2.group(3)]&0xff
    elif m=='strb':
        mm=re.match(r'w(\d+), \[x(\d+)(?:, #(0x[0-9a-f]+|\d+))?\]', op)
        if mm:
            y='w'+mm.group(1); xb='x'+mm.group(2)
            off=int(mm.group(3),0) if mm.group(3) else 0
            if y in K and xb in xreg:
                recs[xreg[xb]+off]=K[y]
print('提取到 (addr->K) 条目:', len(recs))
addrs=sorted(recs)
print('地址范围: 0x%x .. 0x%x'%(addrs[0],addrs[-1]) if addrs else 'none')
# 应用到文件
for va,Kv in recs.items():
    fo=va  # .text va==off? 检查
    # 用段映射: 找包含 va 的 PT_LOAD
# 建 va->file 映射
segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
def foff(va):
    for v,o,fs in segs:
        if v<=va<v+fs: return o+(va-v)
    return None
dec={}
for va,Kv in recs.items():
    fo=foff(va)
    if fo is None: continue
    dec[va]=((Kv-raw[fo])&0xff)^Kv
# 找可读串: 用解出的字节 覆盖原文件, 然后扫
buf=bytearray(raw)
for va,pt in dec.items():
    fo=foff(va)
    if fo is not None: buf[fo]=pt
# 扫串
for va in addrs:
    fo=foff(va)
    if fo is None: continue
    # 从 va 起读直到 null
    s=b''; f2=fo
    while f2<len(buf) and buf[f2]!=0 and 0x20<=buf[f2]<0x7f:
        s+=bytes([buf[f2]]); f2+=1
    if len(s)>=5: print('  0x%x %r'%(va,s[:60]))
