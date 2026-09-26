# -*- coding: utf-8 -*-
"""在 .utoc 里找压缩方法名(Oodle?) + .ucas 数据块抽样。"""
import os, glob
IO=r"C:\Users\20751\Desktop\异环\unpacked\io"
for name in ("global.utoc","pakchunk0-Android_ASTC.utoc","pakchunk1-Android_ASTC.utoc"):
    p=os.path.join(IO,name)
    d=open(p,"rb").read()
    print(f"\n===== {name} =====")
    for pat,lab in ((b"Oodle","ascii-Oodle"), (b"O\x00o\x00d\x00l\x00e\x00","utf16-Oodle"),
                    (b"None","None"), (b"Zlib","Zlib"), (b"Odin","Odin"), (b"oodle","oodle")):
        i=d.find(pat)
        if i>=0: print(f"  {lab} @+0x{i:x}: ...{d[max(0,i-8):i+40]}")
    # 若没找到, dump header 尾部 256B (方法名通常紧跟 header)
    print(f"  [+0x90:+0x130]: {d[0x90:0x130]}")
# .ucas 头
for ucas in ("global.ucas",):
    p=os.path.join(IO,ucas)
    d=open(p,"rb").read()
    print(f"\n===== {ucas} ({len(d)}B) 头 64B =====")
    print(" ", d[:64].hex())
