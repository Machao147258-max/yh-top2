# -*- coding: utf-8 -*-
"""扫 key 样字符串: 32/64 位十六进制 + 加密相关关键字。"""
import re, os
SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
raw = open(SO, "rb").read()
print(f"文件 {len(raw)} 字节")

# 1) 提取可打印串 (>=6)
strs = re.findall(rb"[\x20-\x7e]{6,200}", raw)
print(f"可打印串 {len(strs)} 条")

# 2) 32/64 位纯十六进制串
hexre = re.compile(rb"^[0-9a-fA-F]{32}(?:[0-9a-fA-F]{32})?$")
hexkeys = set()
for s in strs:
    if hexre.match(s):
        hexkeys.add(s)
print(f"\n== 32/64 位十六进制串 ({len(hexkeys)}) ==")
for k in sorted(hexkeys)[:60]:
    print("  ", k.decode(), f"({len(k)//2} 字节)")

# 3) 加密关键字
KW = [b"AES=", b"-AES", b"EncryptionKey", b"SigningKey", b"Crypto.json",
      b"FAES", b"FEncryptionKey", b"AESKey", b"EncryptKey", b"PakSigningKeys",
      b"DecryptionKey", b"bEnablePakSigning", b"CryptoKeys"]
print(f"\n== 加密关键字 ==")
for kw in KW:
    i = 0; hits = []
    while True:
        i = raw.find(kw, i)
        if i < 0: break
        hits.append(i); i += 1
    if hits:
        print(f"  {kw.decode():20s} {len(hits)} 处")
        for h in hits[:4]:
            ctx = raw[max(0,h-30):h+70]
            ctx = bytes(c if 32<=c<127 else 46 for c in ctx)
            print(f"      0x{h:x}: {ctx.decode()}")
