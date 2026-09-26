# -*- coding: utf-8 -*-
"""定位 assert 串 vaddr(在 seg.bin) → 扫 .text 的 adrp/add 引用 → 找 DEX 解析代码。"""
import capstone,re
from elftools.elf.elffile import ELFFile
seg=open(r"C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin","rb").read()
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ins=list(md.disasm(td, tb))
# adrp/add 目标解析
addrs={}
adrp={}
def setadrp(x):
    m=re.search(r"x(\d+), #(0x[0-9a-f]+)", x.op_str)
    if m: adrp[int(m.group(1))]=int(m.group(2),16)
want=[b"op >= 0 && op < kNumPackedOpcodes", b"idx < pDexFile->pHeader->methodIdsSize",
      b"jvalue InterpretInternal", b"idx < pDexFile->pHeader->stringIdsSize"]
tv={}
for w in want:
    i=seg.find(w)
    tv[w]=(i, seg[i:i+len(w)])  # vaddr=offset in seg (module base maps vaddr0)
    print(f"{w[:40]!r} vaddr=0x{i:x}")
# 找引用
targets={i for i,_ in tv.values()}
for x in ins:
    if x.mnemonic=="adrp": setadrp(x); continue
    if x.mnemonic=="add":
        m=re.search(r"x(\d+), x(\d+), #(0x[0-9a-f]+)", x.op_str)
        if m:
            d,s,off=int(m.group(1)),int(m.group(2)),int(m.group(3),16)
            if s in adrp:
                a=adrp[s]+off
                if a in targets: print(f"  REF 0x{a:x} at 0x{x.address:x}: {x.mnemonic} {x.op_str}")
