# -*- coding: utf-8 -*-
"""grep libUnreal 里 crypto/key/pak 相关字符串。"""
import re
raw=open(r"D:\qwork\libUnreal.so","rb").read()
KWS=[b"Crypto",b"AESKey",b"EncryptionKey",b"PakEncryption",b"RegisterKey",b"FAESKey",
     b"PakKey",b"DecryptKey",b"SetKey",b"CryptoKeys",b"IFileCrypto",b"FileCrypto",
     b"aes_key",b"OodleKey",b"secondary",b"DefaultKey",b"cryptokey"]
seen={}
for kw in KWS:
    idxs=[m.start() for m in re.finditer(re.escape(kw),raw)]
    if idxs:
        print(f"\n[{kw.decode()}] {len(idxs)} 处")
        for i in idxs[:12]:
            # 取上下文可见串
            a=i
            while a>0 and 0x20<=raw[a-1]<0x7f: a-=1
            b=i+len(kw)
            while b<len(raw) and 0x20<=raw[b]<0x7f: b+=1
            print(f"   0x{i:x}: {raw[a:b][:120]!r}")
