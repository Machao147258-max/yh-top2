# -*- coding: utf-8 -*-
"""检查 utoc TOC 是否明文: 熵 + 明文路径/字符串。"""
import os, math, collections, re
IO=r"C:\Users\20751\Desktop\异环\unpacked\io"
def H(bs):
    c=collections.Counter(bs); n=len(bs)
    return -sum(v/n*math.log2(v/n) for v in c.values()) if n else 0
for name in ("pakchunk0-Android_ASTC.utoc","pakchunk1-Android_ASTC.utoc","global.utoc"):
    p=os.path.join(IO,name); d=open(p,"rb").read()
    print(f"\n===== {name} ({len(d)}B) =====")
    print(f"  熵 [0x90:+0x8000] = {H(d[0x90:0x90+0x8000]):.4f}")
    print(f"  熵 末段 [0.9len:] = {H(d[int(len(d)*0.9):]):.4f}")
    # 明文串
    for pat in (b"/Game/", b".uasset", b".uexp", b"/Script/", b"Content/", b".ubulk", b"/HT/"):
        c=d.count(pat)
        if c: print(f"  明文 {pat!r}: {c} 次")
    ss=re.findall(rb"[\x20-\x7e]{8,}", d[0x90:0x90+0x8000])
    print(f"  头部区可读串 {len(ss)} 条, 前8: {[s[:40].decode('latin1') for s in ss[:8]]}")
    ss2=re.findall(rb"[\x20-\x7e]{8,}", d)
    print(f"  全文件可读串 {len(ss2)} 条, 抽样: {[s[:36].decode('latin1') for s in ss2[:5]]}")
