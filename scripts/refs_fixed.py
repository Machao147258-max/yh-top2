"""修正版引用扫描: adrp 后 1~3 条内找 add (Rn==Rd)"""
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

TARGETS = {
    0x9512d6: "Handshake completed.",
    0x9512eb: "%s failed. sslresult = %d, %s",
    0x951314: "OpenSSL Verification failed at depth",
    0x951287: "SSL_CTX_new failed.",
    0x9512af: "SSL version: %d, %s",
    0x95126d: "ct_cacert.pem",
    0x946da1: "Connect %s:%d, isSsl=%d, index=%d",
    0x9512b0: "?",
    0x9513f9: "SSLSocket",
}
refs = {t: [] for t in TARGETS}
for i in range(n-4):
    insn = words[i]
    if (insn & 0x9F000000) != 0x90000000:
        continue
    rd = insn & 0x1F
    imm = (((insn>>5)&0x7FFFF)<<2)|((insn>>29)&3)
    va = base_va+i*4
    tp = (va & ~0xFFF) + (se(imm,21)<<12)
    if tp != 0x951000 and tp != 0x946000: 
        continue
    for k in (1,2,3):
        nx = words[i+k]
        if (nx & 0xFFC00000) == 0x91000000 and ((nx>>5)&0x1F)==rd:
            full = tp + ((nx>>10)&0xFFF)
            if full in TARGETS: refs[full].append(va)
            break

for t,name in TARGETS.items():
    print(f"[{name}] {t:#x}: {[hex(x) for x in refs[t]]}")
