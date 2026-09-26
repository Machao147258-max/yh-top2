"""列出所有指向指定页的 ADRP 引用 (放宽条件)"""
from elftools.elf.elffile import ELFFile
import struct
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
elf = ELFFile(open(SO, "rb"))
base_va, base_off, size = 0, 0, 0
for seg in elf.iter_segments():
    if seg.header.p_type == 'PT_LOAD' and (seg.header.p_flags & 1):
        base_va, base_off, size = seg.header.p_vaddr, seg.header.p_offset, seg.header.p_filesz
code = data[base_off:base_off + size]
n = len(code)//4
words = struct.unpack_from(f"<{n}I", code, 0)

def sign_ext(v, b):
    m = 1 << (b-1); return (v ^ m) - m

PAGES = {0x951000: "SSLContext区", 0x96e000: "curl-vtls区", 0x946000: "Connect日志区", 0x8f9000: "isSsl区", 0x96d000: "SSL_read区"}
hits = {p: [] for p in PAGES}
for i in range(n):
    insn = words[i]
    if (insn & 0x9F000000) != 0x90000000:
        continue
    immlo = (insn >> 29) & 3; immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    va = base_va + i*4
    tp = (va & ~0xFFF) + (sign_ext(imm,21) << 12)
    if tp in PAGES:
        # 看下一条
        nxt = words[i+1]
        kind = "?"
        lo = ""
        if (nxt & 0xFFC00000) == 0x91000000:
            kind = "add"; lo = f"{((nxt>>10)&0xFFF):#x}"
        elif (nxt & 0xFFC00000) == 0xF9400000:
            kind = "ldr"; lo = f"{(((nxt>>10)&0xFFF)*8):#x}"
        hits[tp].append((va, kind, lo))

for p, name in PAGES.items():
    print(f"\n=== 页 {p:#x} ({name}) 共 {len(hits[p])} 处 ===")
    for va, kind, lo in hits[p]:
        print(f"   ref@ {va:#x}  {kind} #{lo}")
