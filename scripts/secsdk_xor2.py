# -*- coding: utf-8 -*-
"""libsecsdk .data 多字节异或爆破 + 判断是否含加密DEX。"""
import re
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
elf=ELFFile(open(SO,"rb")); dt=elf.get_section_by_name('.data'); dd=dt.data()
def score(dec):
    runs=re.findall(rb"[A-Za-z][ -~]{5,}", dec)
    en=[r for r in runs if b" " in r and sum(65<=c<=122 for c in r)/len(r)>0.75]
    return len(en), en
best=None
for k1 in range(1,256):
    for k2 in range(256):
        dec=bytes(c^(k1 if i%2==0 else k2) for i,c in enumerate(dd))
        n,en=score(dec)
        if best is None or n>best[0]:
            best=(n,k1,k2,en[:8])
print("2字节最佳:", best[1:3], "命中英文串数:", best[0])
for r in best[3]: print("   ",r[:78])
# 试 4 字节 (取2字节结果作启发—先看 3字节)
best3=None
for k1 in range(1,256):
    for k2 in range(0,256,1):
        for k3 in (0x00,0x20,0xff, best[1], best[2]):
            dec=bytes(c^[k1,k2,k3][i%3] for i,c in enumerate(dd))
            n,en=score(dec)
            if best3 is None or n>best3[0]: best3=(n,k1,k2,k3,en[:8])
print("\n3字节最佳:", best3[1:4], "命中:", best3[0])
for r in best3[4]: print("   ",r[:78])
# 是否像DEX: 解后找 "dex\n"/"L...;"
keyv=None
cand=bytes(c^(best[1] if i%2==0 else best[2]) for i,c in enumerate(dd))
print("\n2字节解后含 'dex' / 'Ljava' / 'dex\\n':", b"dex" in cand, b"Ljava" in cand, b"dex\n" in cand)
