"""验证 pinning + 定位 Connect 层 + curl_easy_setopt 调用者"""
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

# 1. pin 相关数据字符串 (跳过 CA bundle 区 0x8f0000-0x9a0000? 实际 bundle 从 0x8fd6f4)
import re
print("=== pin/公钥 数据字符串 ===")
for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
    s = m.group()
    o = m.start()
    if o > 0x940000: continue   # 只看代码段前段
    low = s.lower()
    if b'sha256//' in low or b'pin-' in low or b'sha256:' in low:
        print(f"  off={o:#x}  {s[:80].decode('latin1')}")

# 2. movz 32/64 of 0x27F6
print("\n=== movz wN/xN,#0x27F6 (CURLOPT_PINNEDPUBLICKEY) ===")
for i in range(n):
    insn = words[i]
    if (insn & 0xFF800000) in (0x52800000, 0xD2800000) and ((insn>>5)&0xFFFF)==0x27F6:
        print(f"  @ {base_va+i*4:#x}: {insn:#010x}")

# 3. Connect 日志字符串 (0x946da1) 引用点
def sign_ext(v,b):
    m=1<<(b-1); return (v^m)-m
tgt = 0x946da1
print(f"\n=== 'Connect %s:%d, isSsl' ({tgt:#x}) 引用点 ===")
for i in range(n-1):
    insn=words[i]
    if (insn&0x9F000000)!=0x90000000: continue
    imm=(((insn>>5)&0x7FFFF)<<2)|((insn>>29)&3)
    va=base_va+i*4
    tp=(va&~0xFFF)+(sign_ext(imm,21)<<12)
    nx=words[i+1]
    if (nx&0xFFC00000)==0x91000000 and ((nx>>5)&0x1F)==(insn&0x1F) and tp+((nx>>10)&0xFFF)==tgt:
        print(f"  ref @ {va:#x}")
