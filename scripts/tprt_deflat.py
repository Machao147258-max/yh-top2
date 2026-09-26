# -*- coding: utf-8 -*-
"""libtprt 反平坦化: 找出状态机分发器 + 每个基本块设置的状态 -> 重建转移图。
用法: tprt_deflat.py <start_hex> <len_hex>
"""
import capstone, re, sys
from elftools.elf.elffile import ELFFile
from collections import Counter
P=r'D:\qwork\libtprt.so'
elf=ELFFile(open(P,'rb')); txt=elf.get_section_by_name('.text')
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(txt.data(), txt['sh_addr']))
# 只保留目标函数范围
start=int(sys.argv[1],16); ln=int(sys.argv[2],16)
fn=[x for x in ins if start<=x.address<start+ln]
addr2i={x.address:i for i,x in enumerate(fn)}
# 1. 找分发器: 被 b/b.cond 指向最多的地址
bt=Counter()
for x in fn:
    if x.mnemonic.startswith('b'):
        m=re.search(r'#(0x[0-9a-f]+)', x.op_str)
        if m:
            t=int(m.group(1),16)
            if start<=t<start+ln: bt[t]+=1
disp=bt.most_common(1)[0][0] if bt else None
print('分发器(最多被跳)=0x%x, 入边=%d'%(disp, bt[disp]) if disp else '无')
# 2. 状态寄存器: 分发器里被 cmp 最多的寄存器
streg=None
c=Counter()
for x in fn:
    if x.mnemonic in ('cmp','subs','and'):
        m=re.match(r'(w\d+)', x.op_str)
        if m: c[m.group(1)]+=1
streg=c.most_common(1)[0][0] if c else None
print('状态寄存器=',streg)
# 3. 每个块设置的状态: 找 mov/movk 该寄存器(可能成对 mov+movk)
def collect_state(i):
    # 往前找最近的 mov/movk 序列
    lo=0; val=0
    j=i
    while j>=0 and (i-j)<20:
        y=fn[j]
        m=re.match(r'(w\d+), #(0x[0-9a-f]+|\d+)', y.op_str)
        if m and m.group(1)==streg:
            v=int(m.group(2),0)&0xffffffff
            if y.mnemonic=='mov': val=v; lo=j; break
            if y.mnemonic=='movk':
                sh=int(re.search(r'lsl #(\d+)', y.op_str).group(1)) if 'lsl' in y.op_str else 0
                val |= (v&0xffff)<<sh
            if y.mnemonic=='movz': val|=v<<(int(re.search(r'lsl #(\d+)',y.op_str).group(1)) if 'lsl' in y.op_str else 0)
        j-=1
    return val
print('\n--- 设置状态的位置(块尾) ---')
for i,x in enumerate(fn):
    if x.mnemonic.startswith('b'):
        m=re.search(r'#(0x[0-9a-f]+)', x.op_str)
        t=int(m.group(1),16) if m else 0
        st=collect_state(i) if streg else 0
        print('  0x%x -> 0x%x  %s   [state=0x%x]'%(x.address, t, x.mnemonic, st))
