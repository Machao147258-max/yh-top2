# -*- coding: utf-8 -*-
"""定位 libUnreal.so 中引用 'OodleLZ_Decompress' / 'OodleLZ_Compress' 字符串的代码地址。
方法: adrp 向量化扫描 -> 命中目标页 -> capstone 反汇编候选点看是否 add/ldr 接同一串。"""
import struct, numpy as np, capstone

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
TARGETS = [b"OodleLZ_Decompress", b"OodleLZ_Compress", b"OodleLZ_Decompress"]


def parse_phdrs(path):
    with open(path, "rb") as f:
        f.seek(0); eh = f.read(0x40)
        e_phoff = struct.unpack_from("<Q", eh, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", eh, 0x36)[0]
        e_phnum = struct.unpack_from("<H", eh, 0x38)[0]
        f.seek(e_phoff); ph = f.read(e_phentsize * e_phnum)
    segs = []
    for i in range(e_phnum):
        o = i * e_phentsize
        p_type = struct.unpack_from("<I", ph, o)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_flags = struct.unpack_from("<I", ph, o + 4)[0]
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<5Q", ph, o + 8)
        segs.append(dict(off=p_offset, vaddr=p_vaddr, filesz=p_filesz, flags=p_flags))
    return segs


def foff_to_vaddr(segs, foff):
    for s in segs:
        if s["off"] <= foff < s["off"] + s["filesz"]:
            return s["vaddr"] + (foff - s["off"]), s
    return None, None


def main():
    segs = parse_phdrs(SO)
    print("PT_LOAD 段:")
    for s in segs:
        r = "R" if s["flags"] & 4 else "-"
        w = "W" if s["flags"] & 2 else "-"
        x = "X" if s["flags"] & 1 else "-"
        print(f"  off=0x{s['off']:08x} vaddr=0x{s['vaddr']:08x} filesz=0x{s['filesz']:x} [{r}{w}{x}]")

    data = open(SO, "rb").read()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    # RX 段
    rx = [s for s in segs if s["flags"] & 1][0]
    seg = np.frombuffer(data[rx["off"]:rx["off"] + rx["filesz"]], dtype="<u4")
    base = rx["vaddr"]
    idx = np.arange(len(seg), dtype=np.int64)
    pcs = (base + idx * 4).astype(np.int64)

    # adrp 掩码
    is_adrp = (seg & 0x9F000000) == 0x90000000
    immlo = ((seg >> 29) & 0x3).astype(np.int64)
    immhi = ((seg >> 5) & 0x7FFFF).astype(np.int64)
    imm = (immlo | (immhi << 2))
    imm = np.where(imm >= (1 << 20), imm - (1 << 21), imm) << 12       # 符号扩展 21bit
    tgt_page = (pcs & ~0xFFF) + imm

    for name in [b"OodleLZ_Decompress", b"OodleLZ_Compress"]:
        st = data.find(name)
        if st < 0:
            print(f"\n[!] 未找到串 {name}"); continue
        sv, sseg = foff_to_vaddr(segs, st)
        page = sv & ~0xFFF
        print(f"\n=== '{name.decode()}' 文件偏移=0x{st:x} vaddr=0x{sv:x} page=0x{page:x} ===")
        hit = np.where(is_adrp & (tgt_page == page))[0]
        print(f"命中 adrp 目标页的指令数: {len(hit)}")
        for h in hit[:20]:
            pc = int(pcs[h])
            print(f"\n  adrp @ 0x{pc:x}")
            code = data[pc - rx["vaddr"] + rx["off"]: pc - rx["vaddr"] + rx["off"] + 16]
            for ins in md.disasm(code, pc):
                print(f"    0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")


if __name__ == "__main__":
    main()
