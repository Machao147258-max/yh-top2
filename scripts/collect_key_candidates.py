# -*- coding: utf-8 -*-
"""从 libUnreal.so 提取 32 字节候选密钥：adrp+add 指向的常量。"""
import struct, numpy as np, capstone

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"

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

def main():
    segs = parse_phdrs(SO)
    data = open(SO, "rb").read()
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
    is_add64 = (words & 0xFF800000) == 0x91000000
    add_imm = (words >> 10) & 0xFFF
    add_rn = (words >> 5) & 0x1F

    # 收集 adrp+add 目标地址
    targets = set()
    cand = np.where(is_adrp)[0]
    for i in cand:
        for d in (1, 2):
            j = i + d
            if j >= n: continue
            if is_add64[j] and rd[i] == add_rn[j]:
                targets.add(int(tgt[i]) + int(add_imm[j]))
    print(f"adrp+add 目标地址数: {len(targets)}")

    # 取 32 字节（须落在 R 或 RW 文件内段）
    RSRANGE = []
    for s in segs:
        if s["filesz"] and (s["flags"] & 4):
            RSRANGE.append((s["vaddr"], s["vaddr"] + s["filesz"], s["off"]))

    def read32(va):
        for (a, b, off) in RSRANGE:
            if a <= va and va + 32 <= b:
                fo = off + (va - a)
                return data[fo:fo + 32]
        return None

    keys = {}
    for va in targets:
        b32 = read32(va)
        if b32 and len(b32) == 32:
            # 过滤明显是文本/空 的
            if b32.count(0) > 8:   # 太多 0 不像密钥
                continue
            keys[b32] = va
    print(f"32字节候选（去重、去零）: {len(keys)}")
    for k, va in list(keys.items())[:10]:
        print(f"  0x{va:08x}: {k.hex()}")

if __name__ == "__main__":
    main()
