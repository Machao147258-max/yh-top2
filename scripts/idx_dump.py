# -*- coding: utf-8 -*-
"""看 pak 索引区(0x2f41376,0x11320)的原始结构与可读串。"""
import re
PAK = r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
d = open(PAK, "rb").read()
io, sz = 0x2f41376, 0x11320
idx = d[io:io+sz]
print("=== 索引头部 128B ===")
for i in range(0,128,16):
    print(f"+{i:04x}: " + " ".join(f"{b:02x}" for b in idx[i:i+16]) + "  " +
          "".join(chr(b) if 32<=b<127 else "." for b in idx[i:i+16]))
# 可读串
ss = re.findall(rb"[\x20-\x7e]{4,}", idx)
print(f"\n可读串 {len(ss)} 条, 前 40:")
for s in ss[:40]:
    print("  ", s.decode("latin1"))
# 熵
import math, collections
def H(bs):
    c=collections.Counter(bs); n=len(bs)
    return -sum(v/n*math.log2(v/n) for v in c.values())
print(f"\n整体熵 = {H(idx):.4f}")
print(f"前 4KB 熵 = {H(idx[:4096]):.4f}")
print(f"前 64B 熵 = {H(idx[:64]):.4f}")
# 是否 Oodle? 看有无 "b" 开头 或 已知头部
print(f"\n前 4 字节: {idx[:4].hex()} = {int.from_bytes(idx[:4],'little')}")
