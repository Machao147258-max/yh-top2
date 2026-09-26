# -*- coding: utf-8 -*-
"""各 SO: 签名/证书/完整性 相关字符串 + 上下文。"""
import os
W=r"C:\Users\20751\Desktop\异环\unpacked\so"
SOS=["libsecsdk.so","libthemis.so","libmxcore.so","libUnreal.so","libDfga_Catch.so","libclient.so"]
KW=[b"signature",b"Signature",b"certificate",b"Certificate",b"X509",b"META-INF",b".RSA",
    b"SHA-256",b"SHA256",b"MessageDigest",b"GET_SIGNATURES",b"verify",b"integrity",
    b"tamper",b"digest",b"checksum",b"crc32",b"getPackageInfo",b"PackageManager",
    b"apk",b".sf",b"CERT",b"publicKey",b"keystore",b"checkSign"]
def ctx(raw,i,n=40):
    a=max(0,i-n); b=min(len(raw),i+n)
    seg=raw[a:b]
    out=''.join(chr(c) if 32<=c<127 else '.' for c in seg)
    return out
for so in SOS:
    p=os.path.join(W,so)
    if not os.path.exists(p): continue
    raw=open(p,"rb").read()
    print(f"\n===== {so} ({len(raw)}B) =====")
    for kw in KW:
        i=raw.find(kw)
        if i!=-1:
            print(f"  {kw.decode():16s} x{raw.count(kw):<4} @0x{i:x}: {ctx(raw,i)}")
