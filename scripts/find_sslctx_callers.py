"""定位 _InitSSL 函数起点 + 全量扫 BL 调用者 + 扫证书/pinning 相关字符串"""
from elftools.elf.elffile import ELFFile
import struct
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
elf = ELFFile(open(SO, "rb"))
base_va, size = 0, 0
for seg in elf.iter_segments():
    if seg.header.p_type == 'PT_LOAD' and (seg.header.p_flags & 1):
        base_va, size = seg.header.p_vaddr, seg.header.p_filesz
n = size // 4
words = struct.unpack_from(f"<{n}I", data, 0)
RET = 0xd65f03c0

def find_start(addr):
    i = (addr - base_va)//4
    while i > 0 and words[i] & 0xFFFFFFFF != RET:
        i -= 1
    return base_va + (i+1)*4

init = find_start(0x2bb69c)
print(f"[*] _InitSSL 函数起点: {init:#x}")

def find_callers(target):
    out = []
    for i in range(n):
        insn = words[i]
        if (insn & 0xFC000000) == 0x94000000:   # BL
            imm = insn & 0x03FFFFFF
            if imm & 0x02000000: imm |= ~0x03FFFFFF
            va = base_va + i*4
            if va + (imm<<2) == target:
                out.append(va)
    return out

print(f"[*] _InitSSL 调用者: {[hex(x) for x in find_callers(init)]}")

# 证书/私钥/pinning 相关字符串
import re
pat = re.compile(rb"[\x20-\x7e]{4,}")
keys = [b'cert', b'pinn', b'.pem', b'.crt', b'client.c', b'SSL_CTX_use', b'private', b'PRIVATE']
seen = set()
print("\n=== 证书/密钥/pinning 相关字符串 ===")
for m in pat.finditer(data):
    s = m.group()
    if len(s) > 100: continue
    low = s.lower()
    if any(k in low for k in [b'pinned', b'ssl_con', b'.pem', b'use_certificate', b'client.crt', b'private_key']):
        t = s.decode('latin1').strip()
        if t in seen: continue
        seen.add(t)
        print(f"  off={m.start():#08x}  {t}")
print(f"共 {len(seen)} 条")
