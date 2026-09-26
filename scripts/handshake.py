"""扫握手函数: 引用 0x9512d6(Handshake completed) / 0x9512eb(%s failed sslresult)"""
import struct
from elftools.elf.elffile import ELFFile
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
elf = ELFFile(open(SO, "rb"))
base_va, size = 0, 0
for seg in elf.iter_segments():
    if seg.header.p_type == 'PT_LOAD' and (seg.header.p_flags & 1):
        base_va, size = seg.header.p_vaddr, seg.header.p_filesz
n = size//4
words = struct.unpack_from(f"<{n}I", data, 0)
def se(v,b):
    m=1<<(b-1); return (v^m)-m
TG = {0x9512d6:"Handshake completed.", 0x9512eb:"%s failed. sslresult=%d,%s", 0x951260:"?"}
seen=set()
for i in range(n-1):
    insn=words[i]
    if (insn&0x9F000000)!=0x90000000: continue
    imm=(((insn>>5)&0x7FFFF)<<2)|((insn>>29)&3)
    va=base_va+i*4
    tp=(va&~0xFFF)+(se(imm,21)<<12)
    if tp != 0x951000: continue
    nx=words[i+1]
    if (nx&0xFFC00000)==0x91000000 and ((nx>>5)&0x1F)==(insn&0x1F):
        lo=(nx>>10)&0xFFF
        if lo in (0x2d6,0x2eb,0x2d0,0x2f0):
            print(f"  ref@{va:#x}  -> 0x951{lo:03x}")
