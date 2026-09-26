# -*- coding: utf-8 -*-
"""找 libUnreal.so 中读写 Oodle 全局指针(0xe63d000 页)的代码，定位注册点。"""
import struct, numpy as np, capstone

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
PAGE = 0xe63d000

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
md.detail = True

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

hits = np.where(is_adrp & (tgt == PAGE))[0]
print(f"引用 page 0x{PAGE:x} 的 adrp 数: {len(hits)}\n")

# 只看写了该页的（STR 系列）。先找有 str/strb/stp 且目标寄存器 == adrp 目的寄存器 的
STR = {"str", "strb", "strh", "stur", "sturb", "stp"}
shown = 0
for h in hits:
    pc = int(pcs[h])
    off = pc - rx["vaddr"] + rx["off"]
    code = data[off - 4: off + 40]
    insns = list(md.disasm(code, pc - 4))
    # 是否含 store
    has_store = any(i.mnemonic in STR for i in insns)
    tag = "  <== 可能是注册/写" if has_store else ""
    print(f"--- 0x{pc:x}{tag}")
    for i in insns[:8]:
        print(f"    0x{i.address:x}: {i.mnemonic} {i.op_str}")
    shown += 1
    if shown >= 40:
        print("... (截断)")
        break
