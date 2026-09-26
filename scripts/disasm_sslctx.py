"""反汇编 SSLContext _InitSSL 区域 + 列出 BL 目标"""
import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def disasm(start, end):
    print(f"\n=== {start:#x}..{end:#x} ===")
    code = data[start:end]
    for insn in MD.disasm(code, start):
        mark = ""
        if insn.mnemonic == "bl" and insn.op_str.startswith("#"):
            mark = f"   -> {int(insn.op_str[1:],16):#x}"
        if insn.mnemonic == "ret":
            print(f"  {insn.address:#x}: ret"); 
            continue
        print(f"  {insn.address:#x}: {insn.mnemonic:7s} {insn.op_str}{mark}")

# _InitSSL 引用点附近 (0x2bb69c)
disasm(0x2bb640, 0x2bb730)
