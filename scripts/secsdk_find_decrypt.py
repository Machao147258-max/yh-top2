# -*- coding: utf-8 -*-
"""找 libsecsdk .data(0x62000+) 的写入点(原地解密循环) + 看 0x8c80-0x9100 那段调用。"""
import capstone
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tbase=txt['sh_addr']; tdata=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

# 1) 找 adrp #0x62000 -> 之后用该寄存器做 strb/str/add (原地写)
print("=== adrp #0x62000 后紧跟的 写/加减 ===")
last_adrp=None
cnt=0
for ins in md.disasm(tdata, tbase):
    if ins.mnemonic=="adrp":
        try:
            v=int(ins.op_str.split('#')[1],16); reg=ins.op_str.split(',')[0].strip()
            last_adrp=(v,reg,ins.address)
        except: pass
    elif last_adrp and last_adrp[0]==0x62000:
        reg=last_adrp[1]
        if reg in ins.op_str and ins.mnemonic in ("strb","str","stur","sturb","add","sub","ldrb","ldr"):
            if cnt<40: print(f"  0x{ins.address:x}: {ins.mnemonic} {ins.op_str}   (adrp@0x{last_adrp[2]:x})")
            cnt+=1
    else:
        last_adrp=None
print(f"  ... 共 {cnt} 处")

# 2) 反汇编 0x8c80-0x9100 (长串调用)
print("\n=== 0x8c80-0x9100 ===")
fo=0x8c80-tbase
for ins in md.disasm(tdata[fo:fo+0x480], 0x8c80):
    t=f"{ins.mnemonic} {ins.op_str}"
    if ins.mnemonic in ("bl","b"):
        try:
            off=int(ins.op_str.split('#')[1],16); t+=(f" ->0x{off:x}")
        except: pass
    print(f"0x{ins.address:x}: {t}")
    if ins.address>0x9060: break
f.close()
