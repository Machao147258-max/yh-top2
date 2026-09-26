# -*- coding: utf-8 -*-
import struct
SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
f = open(SO, "rb"); eh = f.read(0x40)
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
    segs.append((va, fs, ms, fl))
    r = "R" if fl & 4 else "-"; w = "W" if fl & 2 else "-"; x = "X" if fl & 1 else "-"
    print(f"vaddr=0x{va:08x} filesz=0x{fs:x} memsz=0x{ms:x} [{r}{w}{x}] end(v)=0x{va+ms:x}")

for tgt in (0xe63d000, 0xe63d578, 0xe63d590, 0xe63d5c8):
    loc = "未映射"
    for va, fs, ms, fl in segs:
        if va <= tgt < va + ms:
            loc = "文件内(可静态读)" if tgt < va + fs else "BSS(运行时,文件内=0)"
            break
    print(f"  0x{tgt:x} -> {loc}")
