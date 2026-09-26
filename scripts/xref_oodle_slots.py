# -*- coding: utf-8 -*-
"""定向：找 0xe63d000 + 0x578 / 0x590 的读写点（Oodle 指针槽）。"""
import struct, numpy as np, capstone

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
TARGET_OFFS = {0x578, 0x590, 0x568, 0x588}

def parse_phdrs(path):
    f = open(path, "rb"); eh = f.read(0x40)
    e_phoff = struct.unpack_from("<Q", eh, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", eh, 0x36)[0]
    e_phnum = struct.unpack_from("<H", eh, 0x38)[0]
    f.seek(e_phoff); ph = f.read(e_phentsize * e_phnum)
    segs = []
    for i in range(e_phnum):
        o = i * e_phentsize
        if struct.unpack_from("<I", ph, o)[0] != 1: continue
        fl = struct.unpack_from("<I", ph, o + 4)[0]
        off, va, _pa, fs, ms = struct.unpack_from("<5Q", ph, o + 8)
        segs.append(dict(off=off, vaddr=va, filesz=fs, memsz=ms, flags=fl))
    return segs

segs = parse_phdrs(SO)
data = open(SO, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
rx = [s for s in segs if s["flags"] & 1][0]
words = np.frombuffer(data[rx["off"]:rx["off"] + rx["filesz"]], dtype="<u4")
base = rx["vaddr"]; n = len(words); idx = np.arange(n, dtype=np.int64)
pcs = (base + idx * 4).astype(np.int64)
is_adrp = (words & 0x9F000000) == 0x90000000
immlo = ((words >> 29) & 0x3).astype(np.int64)
immhi = ((words >> 5) & 0x7FFFF).astype(np.int64)
imm = (immlo | (immhi << 2)); imm = np.where(imm >= (1 << 20), imm - (1 << 21), imm) << 12
tgt = (pcs & ~0xFFF) + imm
rd = (words & 0x1F).astype(np.int64)

# ADD imm64
is_add64 = (words & 0xFF800000) == 0x91000000
add_imm = (words >> 10) & 0xFFF
add_rn = (words >> 5) & 0x1F

cand = np.where(is_adrp & (tgt == 0xe63d000))[0]
print(f"adrp→0xe63d000 数: {len(cand)}\n")
seen = set()
for i in cand:
    for d in (1, 2):
        j = i + d
        if j >= n: continue
        if is_add64[j] and rd[i] == add_rn[j] and int(add_imm[j]) in TARGET_OFFS:
            pc = int(pcs[j])
            if pc in seen: continue
            seen.add(pc)
            offn = int(add_imm[j])
            print(f"--- 0x{pc:x}  (reg x{rd[i]}, +0x{offn:x})")
            o = pc - rx["vaddr"] + rx["off"]
            for ins in md.disasm(data[o - 8: o + 28], pc - 8):
                print(f"    0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
