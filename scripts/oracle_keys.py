# -*- coding: utf-8 -*-
"""AES oracle：用候选密钥解密 pak 索引，按"可读路径"打分，找真 key。"""
import struct, numpy as np, os
from Crypto.Cipher import AES

SO  = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
PAK = r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
INDEX_OFF = 0x2f41376
INDEX_SIZE = 0x11320

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

def collect_candidates(so):
    segs = parse_phdrs(so)
    data = open(so, "rb").read()
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
    targets = set()
    for i in np.where(is_adrp)[0]:
        for d in (1, 2):
            j = i + d
            if j < n and is_add64[j] and rd[i] == add_rn[j]:
                targets.add(int(tgt[i]) + int(add_imm[j]))
    # 只读段（R，非 X，非 W）—— 密钥常量通常在 .rodata
    ro = [s for s in segs if (s["flags"] & 4) and not (s["flags"] & 1)]
    out = {}
    for va in targets:
        for s in ro:
            if s["vaddr"] <= va and va + 32 <= s["vaddr"] + s["filesz"]:
                fo = s["off"] + (va - s["vaddr"])
                b = data[fo:fo + 32]
                if b.count(0) <= 4:            # 排除含大量 0 的
                    out[b] = va
                break
    return out

def score(pt):
    if not pt: return 0, 0.0
    printable = sum(1 for c in pt if 0x20 <= c < 0x7f)
    ratio = printable / len(pt)
    # 路径特征加分
    bonus = pt.count(b"/") + pt.count(b".") + pt.count(b"Game") + pt.count(b"Content")
    return bonus, ratio

def main():
    cands = collect_candidates(SO)
    print(f"只读段候选: {len(cands)}")
    with open(PAK, "rb") as f:
        f.seek(INDEX_OFF); enc = f.read(INDEX_SIZE)
    N = min(len(enc), 8192)
    encN = enc[:N]
    results = []
    for k, va in cands.items():
        try:
            pt = AES.new(k, AES.MODE_ECB).decrypt(encN)
        except Exception:
            continue
        bonus, ratio = score(pt)
        results.append((ratio, bonus, va, pt[:64]))
    results.sort(key=lambda x: (-x[0], -x[1]))
    print("\n按 ASCII 占比 Top 15：")
    for ratio, bonus, va, prev in results[:15]:
        print(f"  ratio={ratio:.3f} bonus={bonus} key@0x{va:08x}  {prev[:48]!r}")

if __name__ == "__main__":
    main()
