# -*- coding: utf-8 -*-
"""精确 xref：找 adrp+add 算出精确串地址，以及 RW 段中的字符串指针。"""
import struct, numpy as np, capstone

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
NAMES = [b"OodleLZ_Decompress", b"OodleLZ_Compress",
         b"OodleLZ_Compressor_to_DecodeType", b"Oodle_Core_Malloc_Failed"]


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
        off, va, _pa, fs, _ms = struct.unpack_from("<5Q", ph, o + 8)
        segs.append(dict(off=off, vaddr=va, filesz=fs, flags=fl))
    return segs


def f2v(segs, fo):
    for s in segs:
        if s["off"] <= fo < s["off"] + s["filesz"]:
            return s["vaddr"] + fo - s["off"]
    return None


def main():
    segs = parse_phdrs(SO)
    data = open(SO, "rb").read()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    rx = [s for s in segs if s["flags"] & 1][0]
    rw = [s for s in segs if (s["flags"] & 2) and not (s["flags"] & 1)]

    words = np.frombuffer(data[rx["off"]:rx["off"] + rx["filesz"]], dtype="<u4")
    base = rx["vaddr"]; n = len(words)
    idx = np.arange(n, dtype=np.int64)
    pcs = (base + idx * 4).astype(np.int64)

    is_adrp = (words & 0x9F000000) == 0x90000000
    immlo = ((words >> 29) & 0x3).astype(np.int64)
    immhi = ((words >> 5) & 0x7FFFF).astype(np.int64)
    imm = (immlo | (immhi << 2))
    imm = np.where(imm >= (1 << 20), imm - (1 << 21), imm) << 12
    tgt_page = (pcs & ~0xFFF) + imm
    rd = (words & 0x1F).astype(np.int64)

    # ADD (immediate) 64bit: 0x91xxxxxx ; Rn==rd(adrp), imm12 = 串低12位
    is_add64 = (words & 0xFF800000) == 0x91000000
    add_imm = (words >> 10) & 0xFFF
    add_rn = (words >> 5) & 0x1F

    # RW 段 8 字节指针扫描
    rw_ptrs = {}
    for s in rw:
        vals = np.frombuffer(data[s["off"]:s["off"] + s["filesz"]], dtype="<u8")
        rw_ptrs[s["vaddr"]] = vals

    for nm in NAMES:
        fo = data.find(nm)
        if fo < 0:
            print(f"\n[!] 未找到 {nm}"); continue
        sv = f2v(segs, fo)
        lo = sv & 0xFFF
        print(f"\n=== {nm.decode()}  vaddr=0x{sv:x}  (page 0x{sv & ~0xFFF:x}, lo 0x{lo:x}) ===")

        # 1) adrp + add 精确命中
        cand = np.where(is_adrp & (tgt_page == (sv & ~0xFFF)))[0]
        found = False
        for i in cand:
            for d in (1, 2, 3):
                j = i + d
                if j >= n: continue
                if is_add64[j] and (rd[i] == add_rn[j]) and (add_imm[j] == lo):
                    pc = int(pcs[j])
                    print(f"  [code] 0x{int(pcs[i]):x}: adrp + {d}-> add  => 0x{sv:x}")
                    off = pc - rx["vaddr"] + rx["off"]
                    for ins in md.disasm(data[off - 8:off + 12], pc - 8):
                        print(f"        0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
                    found = True
                    break
        if not found:
            print("  [code] 无精确 adrp+add 引用（可能走指针表/间接）")

        # 2) RW 段指针
        hits = []
        for va, vals in rw_ptrs.items():
            w = np.where(vals == sv)[0]
            for k in w:
                hits.append(va + int(k) * 8)
        if hits:
            for h in hits[:10]:
                print(f"  [RW ptr] @ 0x{h:x} -> 0x{sv:x}")
        else:
            print("  [RW ptr] 无")


if __name__ == "__main__":
    main()
