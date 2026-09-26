"""连接层反汇编 + ct_cacert.pem(0x934a0) 引用扫描"""
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
def se(v,b):
    m=1<<(b-1); return (v^m)-m

# 扫 page 0x934000 -> low12 0x4a0
print("=== 引用 0x934a0 (ct_cacert.pem 表项) ===")
for i in range(n-4):
    insn=words[i]
    if (insn&0x9F000000)!=0x90000000: continue
    rd=insn&0x1F
    imm=(((insn>>5)&0x7FFFF)<<2)|((insn>>29)&3)
    va=base_va+i*4
    tp=(va&~0xFFF)+(se(imm,21)<<12)
    if tp != 0x934000: continue
    for k in (1,2,3):
        nx=words[i+k]
        if (nx&0xFFC00000)==0x91000000 and ((nx>>5)&0x1F)==rd and tp+((nx>>10)&0xFFF)==0x934a0:
            print(f"  ref@{va:#x}"); break

# 连接层反汇编
print("\n=== 连接层 0x1ecea0..0x1ecf60 ===")
for insn in MD.disasm(data[0x1ecea0:0x1ecf60], 0x1ecea0):
    mk=""
    if insn.mnemonic=="bl" and insn.op_str.startswith("#"):
        mk=f"  ; -> {int(insn.op_str[1:],16):#x}"
    print(f"  {insn.address:#x}: {insn.mnemonic:7s} {insn.op_str}{mk}")
