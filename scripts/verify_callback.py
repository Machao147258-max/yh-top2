"""反汇编 verify callback 候选 0x2bba70 + 引用 0x951314 点"""
import struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
elf = ELFFile(open(SO, "rb"))
base_va, size = 0, 0
for seg in elf.iter_segments():
    if seg.header.p_type == 'PT_LOAD' and (seg.header.p_flags & 1):
        base_va, size = seg.header.p_vaddr, seg.header.p_filesz
n = size//4
words = struct.unpack_from(f"<{n}I", data, 0)

# 引用 0x951314 ("OpenSSL Verification failed at depth") 的点
def sign_ext(v,b):
    m=1<<(b-1); return (v^m)-m
print("=== 引用 0x951314 (Verification failed depth) ===")
for i in range(n-1):
    insn=words[i]
    if (insn&0x9F000000)!=0x90000000: continue
    imm=(((insn>>5)&0x7FFFF)<<2)|((insn>>29)&3)
    va=base_va+i*4
    tp=(va&~0xFFF)+(sign_ext(imm,21)<<12)
    nx=words[i+1]
    if (nx&0xFFC00000)==0x91000000 and ((nx>>5)&0x1F)==(insn&0x1F) and tp+((nx>>10)&0xFFF)==0x951314:
        print(f"  ref @ {va:#x}")

# 反汇编 0x2bba60..0x2bbb60
print("\n=== 0x2bba60..0x2bbb60 (verify callback 候选) ===")
for insn in MD.disasm(data[0x2bba60:0x2bbb60], 0x2bba60):
    mk=""
    if insn.mnemonic=="bl" and insn.op_str.startswith("#"):
        mk=f"  ; -> {int(insn.op_str[1:],16):#x}"
    print(f"  {insn.address:#x}: {insn.mnemonic:7s} {insn.op_str}{mk}")
