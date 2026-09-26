# -*- coding: utf-8 -*-
"""找 libsecsdk 里 uncompress 的 PLT 桩 + 调用点 + 读 .data 起始标签串。"""
import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
dyn=elf.get_section_by_name('.dynsym')
# uncompress 的 GOT 偏移
got=None
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection):
        for rel in sec.iter_relocations():
            if dyn.get_symbol(rel['r_info_sym']).name=="uncompress": got=rel['r_offset']
print(f"uncompress GOT offset=0x{got:x}" if got else "无 uncompress GOT")
# .data 起始标签串
dt=elf.get_section_by_name('.data'); db=dt['sh_addr']; dd=dt.data()
print(f"\n.data[0x{db:x}..0x{db+0x60:x}]:")
for i in range(0,0x60,0x10):
    row=dd[i:i+0x10]
    asc=''.join(chr(c) if 32<=c<127 else '.' for c in row)
    print(f"  0x{db+i:x}: {row.hex()}  {asc}")
# 找 PLT 桩: ldr x17,[x16,#got]; 其前有 adrp x16
txt=elf.get_section_by_name('.text'); tbase=txt['sh_addr']; tdata=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
stub=None; prev=None
insns=list(md.disasm(tdata,tbase))
for i,ins in enumerate(insns):
    if ins.mnemonic=="ldr" and ins.op_str.startswith("x17, [x16") and got is not None:
        try:
            off=int(ins.op_str.split('#')[-1].rstrip(']'),16)
            if ins.op_str.split('#')[-1].rstrip(']').startswith('0x') and off==got:
                # 前一/两条应为 adrp x16
                for j in (i-1,i-2):
                    if insns[j].mnemonic=="adrp" and insns[j].op_str.startswith("x16"):
                        stub=insns[j].address; print(f"\nuncompress PLT 桩 @0x{stub:x}")
        except: pass
if stub:
    print("=== bl 到该桩的调用点 ===")
    for ins in insns:
        if ins.mnemonic=="bl":
            try:
                t=int(ins.op_str.split('#')[1],16)
                if abs(t-stub)<8: print(f"  0x{ins.address:x}: bl 0x{t:x}")
            except: pass
f.close()
