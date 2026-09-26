# -*- coding: utf-8 -*-
"""反汇编 0xb586e00-0xb588a00 区域，看 Oodle 名字引用周围是不是"注册表/函数指针表"。"""
import struct, capstone

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False

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

segs = parse_phdrs(SO)
data = open(SO, "rb").read()
rx = [s for s in segs if s["flags"] & 1][0]

def disasm(va_start, va_end):
    fo = va_start - rx["vaddr"] + rx["off"]
    code = data[fo: fo + (va_end - va_start)]
    for ins in md.disasm(code, va_start):
        # 标注是否引用到字符串页
        print(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")

# Oodle 名字附近的两个热点函数
for a, b, tag in [(0xb587200, 0xb587360, "ref@0xb5872e0"),
                  (0xb587480, 0xb587600, "ref@0xb587520")]:
    print(f"\n########## {tag} ##########")
    disasm(a, b)
