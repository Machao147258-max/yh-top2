# -*- coding: utf-8 -*-
"""穷举由 "Oodle" GUID 派生的 AES key/模式。"""
import hashlib
from Crypto.Cipher import AES
PAK=r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
d=open(PAK,"rb").read(); idx=d[0x2f41376:0x2f41376+0x11320]
T="eda462f54e6b194fa3474b5791dfab404b95ca7b"
G=bytes.fromhex("4f6f646c650000000000000000000000")
keys={
 "G16":G, "G+G":G+G, "G+0":G+b"\x00"*16, "0+G":b"\x00"*16+G,
 "oo5pad":b"Oodle"+b"\x00"*27, "oo5repeat":(b"Oodle"*7)[:32],
 "md5G16":hashlib.md5(G).digest(), "sha1G16":hashlib.sha1(G).digest()[:16],
 "sha256G32":hashlib.sha256(G).digest(), "sha256G16":hashlib.sha256(G).digest()[:16],
 "Oodle32":(b"Oodle"+b"\x00"*11)*2,
}
found=False
for kn,k in keys.items():
    for bits in (len(k)*8,):
        for mode in ("ECB","CBC0"):
            try:
                if mode=="ECB": out=AES.new(k,AES.MODE_ECB).decrypt(idx[:len(idx)//16*16])
                else: out=AES.new(k,AES.MODE_CBC,b"\x00"*16).decrypt(idx[:len(idx)//16*16])
            except Exception as e: continue
            if hashlib.sha1(out).hexdigest()==T:
                print(f"★★★ 命中! key={kn}({k.hex()}) mode={mode}"); found=True
print("穷举完成, 命中=",found)
# 也试: 索引可能未 16 对齐, 或需 sha1 of decrypt 全文
print("附加: 试 key=G16 时解密后前16字节各种模式的头部")
k=G
for mode,iv in (("ECB",None),("CBC0",b"\x00"*16)):
    if mode=="ECB": out=AES.new(k,AES.MODE_ECB).decrypt(idx[:16*4])
    else: out=AES.new(k,AES.MODE_CBC,iv).decrypt(idx[:16*4])
    print(f"  {mode}: {out.hex()}")
