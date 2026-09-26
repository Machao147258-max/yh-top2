# -*- coding: utf-8 -*-
"""用 44 个 hex-string 候选(16B) 测 pak 索引。"""
import re, hashlib
from Crypto.Cipher import AES
PAK = r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
SO  = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
IDX_OFF = 0x2f41376; IDX_SIZE = 0x11320
TARGET = "eda462f54e6b194fa3474b5791dfab404b95ca7b"

raw = open(PAK, "rb").read()
idx = raw[IDX_OFF:IDX_OFF+IDX_SIZE]
print(f"索引 {len(idx)} 字节")
h = hashlib.sha1(idx).hexdigest()
print(f"SHA1(密文) = {h}")
print(f"SHA1(目标) = {TARGET}   匹配={h==TARGET}")

# 候选
so = open(SO, "rb").read()
strs = re.findall(rb"[\x20-\x7e]{6,200}", so)
hexre = re.compile(rb"^[0-9a-fA-F]{32}$")
cands = sorted({s for s in strs if hexre.match(s)})
cands.append(b"0123456789ABCDEF0123456789abcdef")
print(f"候选 {len(cands)} 个\n")

def ascii_ratio(b): return sum(1 for c in b if 9<=c<127)/len(b)

best = []
for cs in cands:
    try: key = bytes.fromhex(cs.decode())
    except: continue
    if len(key)!=16: continue
    for mode in ("ECB","CBC"):
        try:
            if mode=="ECB": dec = AES.new(key, AES.MODE_ECB).decrypt(idx[:len(idx)//16*16])
            else: dec = AES.new(key, AES.MODE_CBC, b"\x00"*16).decrypt(idx[:len(idx)//16*16])
        except Exception: continue
        s = hashlib.sha1(dec).hexdigest()
        r = ascii_ratio(dec[:4096])
        if s==TARGET: print(f"*** SHA1 命中! {mode} key={key.hex()} ***")
        best.append((r, mode, key, s))
best.sort(reverse=True)
print("ASCII 比例 Top 10:")
for r,mode,key,s in best[:10]:
    print(f"  {r:.3f} {mode} key={key.hex()} sha1={s[:16]}")
