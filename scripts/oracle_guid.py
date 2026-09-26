# -*- coding: utf-8 -*-
"""把 pak footer 的 GUID("Oodle"+11nul) 当 AES-128 key 测索引。"""
import hashlib
from Crypto.Cipher import AES
PAK=r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
d=open(PAK,"rb").read()
idx=d[0x2f41376:0x2f41376+0x11320]
TARGET="eda462f54e6b194fa3474b5791dfab404b95ca7b"
key=b"Oodle"+b"\x00"*11
print("key =", key.hex())
for mode,iv in (("ECB",None),("CBC0",b"\x00"*16),("CTR0",b"\x00"*16)):
    if mode=="ECB": out=AES.new(key,AES.MODE_ECB).decrypt(idx[:len(idx)//16*16])
    elif mode=="CBC0": out=AES.new(key,AES.MODE_CBC,iv).decrypt(idx[:len(idx)//16*16])
    else: out=AES.new(key,AES.MODE_CTR,nonce=b"",initial_value=0).decrypt(idx[:len(idx)//16*16])
    h=hashlib.sha1(out).hexdigest()
    print(f"{mode}: sha1={h}  命中={h==TARGET}")
    if h==TARGET: print("  ★★★ 命中! ★★★")
# 也试 key = "Oodle" 补齐方式不同: 也许 GUID 取前16 但含更多; 试直接整段 guid 变体
for kdesc,k in [("guid16",d[0x2f997d2:0x2f997d2+16]),
                ("guid_as_is",bytes.fromhex("4f6f646c650000000000000000000000"))]:
    for mode in ("ECB","CBC0"):
        try:
            if mode=="ECB": out=AES.new(k,AES.MODE_ECB).decrypt(idx[:len(idx)//16*16])
            else: out=AES.new(k,AES.MODE_CBC,b"\x00"*16).decrypt(idx[:len(idx)//16*16])
            h=hashlib.sha1(out).hexdigest()
            print(f"{kdesc}/{mode}: key={k.hex()} sha1={h} 命中={h==TARGET}")
        except Exception as e: print(kdesc,mode,"err",e)
