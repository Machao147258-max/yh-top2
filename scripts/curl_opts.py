"""1) dump 0x934a0 附近的 rodata 表  2) 搜 CURLOPT_PINNEDPUBLICKEY(0x27F6)"""
import struct
from elftools.elf.elffile import ELFFile
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
elf = ELFFile(open(SO, "rb"))
base_va, size = 0, 0
for seg in elf.iter_segments():
    if seg.header.p_type == 'PT_LOAD' and (seg.header.p_flags & 1):
        base_va, size = seg.header.p_vaddr, seg.header.p_filesz

def rstr(v):
    if v == 0: return "<null>"
    if v >= len(data): return f"<bad {v:#x}>"
    e = data.find(b"\x00", v)
    return data[v:e].decode('latin1', 'replace')[:60]

print("=== rodata 0x93480..0x934e0 (按指针解释) ===")
for off in range(0x93480, 0x934e0, 8):
    v = struct.unpack_from("<Q", data, off)[0]
    print(f"  {off:#x}: {v:#018x}  -> {rstr(v)}")

# 搜 movz wN,#0x27F6 (CURLOPT_PINNEDPUBLICKEY=10230)
print("\n=== mov wN,#0x27F6 (CURLOPT_PINNEDPUBLICKEY) 位置 ===")
n = size//4
words = struct.unpack_from(f"<{n}I", data, 0)
found = 0
for i in range(n):
    insn = words[i]
    # MOVZ 32bit: 0x52800000 | imm16<<5 | rd
    if (insn & 0xFF800000) == 0x52800000:
        imm = (insn >> 5) & 0xFFFF
        if imm == 0x27F6:
            print(f"  @ {base_va+i*4:#x}: {insn:#010x} (mov w{insn&31}, #0x27F6)")
            found += 1
print(f"共 {found} 处")

# 也搜其它相关 enum: CURLOPT_CAINFO=10065(0x2751), CURLOPT_CAPATH=10097(0x2771), CURLOPT_SSL_VERIFYPEER=64(0x40)
print("\n=== 其他 curl option 立即数 ===")
for name, val in [("CAINFO", 10065), ("CAPATH", 10097), ("SSL_VERIFYHOST", 81), ("SSLCERT", 10025)]:
    cnt = 0
    locs = []
    for i in range(n):
        insn = words[i]
        if (insn & 0xFF800000) == 0x52800000 and ((insn >> 5) & 0xFFFF) == val:
            locs.append(base_va+i*4); cnt += 1
    print(f"  {name}({val}): {cnt} 处 {[hex(x) for x in locs[:8]]}")
