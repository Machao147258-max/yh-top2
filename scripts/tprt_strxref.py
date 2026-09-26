# -*- coding: utf-8 -*-
"""找 libtprt 里引用 ptrace/prctl 等串的代码 (dlsym 绕过 hook 的迹象)。"""
import capstone, re
from elftools.elf.elffile import ELFFile
P=r'D:\qwork\libtprt.so'
raw=open(P,'rb').read()
elf=ELFFile(open(P,'rb'))
segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
def foff(va):
    for v,o,fs in segs:
        if v<=va<v+fs: return o+(va-v)
    return None
# 1. 目标串各次的 vaddr
targets=[b'ptrace',b'prctl',b'syscall',b'frida',b'xposed',b'su',b'/proc',b'TracerPid',b'tp_syscall_imp',b'g_tprt']
strva={}
for t in targets:
    start=0
    while True:
        i=raw.find(t,start)
        if i<0: break
        # 转 vaddr
        va=None
        for v,o,fs in segs:
            if o<=i<o+fs: va=v+(i-o); break
        if va is not None: strva.setdefault(t,[]).append(va)
        start=i+1
# 2. 反汇编 .text, 跟踪 adrp/add, 找指向目标串的引用
txt=elf.get_section_by_name('.text')
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(txt.data(), txt['sh_addr']))
allstr={va:t for t,vas in strva.items() for va in vas}
xreg={}
print('目标串地址:')
for t,vas in strva.items(): print('  %-14s %s'%(t.decode(),[hex(x) for x in vas[:6]]))
print('\n引用:')
for i,x in enumerate(ins):
    if x.mnemonic=='adrp':
        mm=re.match(r'x(\d+), #(0x[0-9a-f]+)',x.op_str)
        if mm: xreg[int(mm.group(1))]=int(mm.group(2),16)
    elif x.mnemonic=='add':
        mm=re.match(r'x(\d+), x(\d+), #(0x[0-9a-f]+)',x.op_str)
        if mm and int(mm.group(2)) in xreg:
            a=xreg[int(mm.group(2))]+int(mm.group(3),16)
            if a in allstr:
                # 看后续 5 条
                nxt=' | '.join('%s %s'%(_m.mnemonic,_m.op_str) for _m in ins[i+1:i+5])
                print('  0x%x ref %r  -> %s'%(x.address, allstr[a].decode(), nxt))
