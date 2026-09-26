"""引用点扫描: ct_cacert.pem / PINNEDPUBLICKEY / 相关"""
from elftools.elf.elffile import ELFFile
import struct, re
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
elf = ELFFile(open(SO, "rb"))
base_va, size = 0, 0
for seg in elf.iter_segments():
    if seg.header.p_type == 'PT_LOAD' and (seg.header.p_flags & 1):
        base_va, size = seg.header.p_vaddr, seg.header.p_filesz
n = size//4
words = struct.unpack_from(f"<{n}I", data, 0)

# 先找 PINNEDPUBLICKEY 字符串偏移
print("=== 含 PINNEDPUBLICKEY / cacert 的字符串 ===")
for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
    s = m.group()
    if b'PINNEDPUBLICKEY' in s or b'cacert' in s or b'CAPATH' in s or b'CAINFO' in s:
        print(f"  off={m.start():#08x}  {s.decode('latin1')}")

def sign_ext(v,b):
    m=1<<(b-1); return (v^m)-m

TARGETS = {
    0x95126d: "ct_cacert.pem",
    0x9671b8: "curl err: pinned public key",
    0x96e838: "vtls: pinned public key!",
    0x994132: "/Users/imac/.../ssl/cert.pem",
}
refs = {t: [] for t in TARGETS}
for i in range(n-1):
    insn = words[i]
    if (insn & 0x9F000000) != 0x90000000: continue
    immlo=(insn>>29)&3; immhi=(insn>>5)&0x7FFFF
    imm=(immhi<<2)|immlo
    va = base_va+i*4
    tp = (va & ~0xFFF) + (sign_ext(imm,21)<<12)
    nxt=words[i+1]
    if (nxt & 0xFFC00000)==0x91000000 and ((nxt>>5)&0x1F)==(insn&0x1F):
        full = tp + ((nxt>>10)&0xFFF)
        if full in TARGETS: refs[full].append(va)

print("\n=== 引用点 ===")
for t,name in TARGETS.items():
    print(f"  [{name}] {t:#x}: {[hex(x) for x in refs[t]]}")
