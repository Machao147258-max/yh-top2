# -*- coding: utf-8 -*-
"""找 libtprt 里调用 tp_syscall_imp(0x146be0) 的地方 + 附近是否设置 prctl/ptrace 号。"""
import capstone, re
from elftools.elf.elffile import ELFFile
P=r'D:\qwork\libtprt.so'
raw=open(P,'rb').read()
elf=ELFFile(open(P,'rb'))
txt=elf.get_section_by_name('.text')
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(txt.data(), txt['sh_addr']))
# 直接 bl 0x146be0
callers=[]
for i,x in enumerate(ins):
    if x.mnemonic in ('bl','b') :
        mm=re.search(r'#(0x[0-9a-f]+)', x.op_str)
        if mm and int(mm.group(1),16)==0x146be0:
            callers.append(i)
print('bl/b -> tp_syscall_imp(0x146be0) 次数:', len(callers))
for i in callers[:25]:
    print('  --- @0x%x ---'%ins[i].address)
    for y in ins[max(0,i-6):i+1]:
        print('      0x%x %s %s'%(y.address,y.mnemonic,y.op_str))
# 也找 mov #167(prctl)/#117(ptrace) 附近有 bl 的
print('\n--- 设 prctl(167)/ptrace(117) 号的地方 ---')
for i,x in enumerate(ins):
    mm=re.match(r'w(\d+), #(167|117)\b', x.op_str) if x.mnemonic in('mov','movz') else None
    if mm:
        print('  @0x%x %s %s'%(x.address,x.mnemonic,x.op_str))
