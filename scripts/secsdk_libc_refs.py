# -*- coding: utf-8 -*-
"""libsecsdk: 每个导入符号被 .text 引用多少次(扫 adrp+ldr GOT)。"""
import capstone, struct
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
dyn=elf.get_section_by_name('.dynsym')
# 符号 -> GOT偏移
got2sym={}
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn','.rela.plt','.rel.plt'):
        for rel in sec.iter_relocations():
            nm=dyn.get_symbol(rel['r_info_sym']).name
            if nm: got2sym[rel['r_offset']]=nm
print(f"GOT 条目 {len(got2sym)}")
# 反汇编 .text, 跟踪 adrp+ldr -> GOT
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
cnt=defaultdict(int)
adrp={}
insns=list(md.disasm(td,tb))
for i,ins in enumerate(insns):
    if ins.mnemonic=="adrp":
        try: adrp[ins.op_str.split(',')[0].strip()]=int(ins.op_str.split('#')[1],16)
        except: pass
    elif ins.mnemonic=="ldr" and ins.op_str.startswith("x") and "[" in ins.op_str:
        # ldr xN, [xM, #off] 或 [xM]
        try:
            left,right=ins.op_str.split("[")
            base=right.split(",")[0].strip()
            off=0
            if "," in right:
                o=right.split(",")[1].strip().rstrip("]")
                off=int(o,16) if o.startswith("0x") else int(o)
            if base in adrp:
                absv=adrp[base]+off
                if absv in got2sym: cnt[got2sym[absv]]+=1
        except: pass
print("\n=== 符号被引用次数(降序) ===")
for nm,c in sorted(cnt.items(), key=lambda x:-x[1]):
    print(f"  {c:4d}  {nm}")
print(f"\n共引用到 {len(cnt)} 个导入符号; 未被引用的导入:")
for nm in sorted(set(dyn.get_symbol(r['r_info_sym']).name for sec in elf.iter_sections() if isinstance(sec,RelocationSection) for r in sec.iter_relocations() if dyn.get_symbol(r['r_info_sym']).name) - set(cnt)):
    if nm: print("   ",nm)
f.close()
