# -*- coding: utf-8 -*-
"""在 libUnreal.so 里找 AES S-box / 逆 S-box / Te0 表 -> 定位 AES 实现。"""
SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
d = open(SO, "rb").read()

SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")   # AES S-box 前16
INV  = bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")   # 逆S-box 前16
TE0  = bytes.fromhex("c66363a5f87c7c84ee777799f67b7b8d")   # T-table 前16
RCON = bytes.fromhex("01020408102040801b36")               # Rcon

for nm, pat in [("S-box", SBOX), ("InvS-box", INV), ("Te0", TE0), ("Rcon", RCON)]:
    i = 0; hits = []
    while True:
        i = d.find(pat, i)
        if i < 0: break
        hits.append(i); i += 1
    print(f"{nm}: {len(hits)} 处  ->  " + ", ".join(hex(h) for h in hits[:8]))
