# -*- coding: utf-8 -*-
"""判断 pak 索引加密模式：ECB 明文(块重复多) vs 压缩/CBC(块几乎全唯一)。"""
import struct, collections, math
from Crypto.Cipher import AES

PAK = r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
IOFF, ISZ = 0x2f41376, 0x11320
with open(PAK,"rb") as f:
    f.seek(IOFF); enc=f.read(ISZ)

def entropy(b):
    if not b: return 0
    c=collections.Counter(b); n=len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())

blocks=[enc[i:i+16] for i in range(0,len(enc)-15,16)]
uniq=len(set(blocks))
print(f"索引大小={len(enc)}  16B块数={len(blocks)}  唯一块={uniq}  唯一率={uniq/len(blocks):.4f}")
print(f"字节熵={entropy(enc):.4f} (8.0≈随机)")

# 首块前 32 字节 (看有没有 magic/结构)
print(f"enc[:32]={enc[:32].hex()}")

# 如果 ECB 明文，密文块重复应与明文重复对应；检查最频繁块
cnt=collections.Counter(blocks)
print("最常见块 Top5:", [(h.hex(),c) for h,c in cnt.most_common(5)])

# 试：假设 ECB 且明文有重复 -> 密文重复；若唯一率≈1.0 则大概率是"压缩后加密"或CBC
