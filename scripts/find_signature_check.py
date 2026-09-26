# -*- coding: utf-8 -*-
"""查签名校验: 各 SO + dex 里的 signature/包校验 关键词; 并读 libUnreal 0xa65a6a 串。"""
import os
W=r"C:\Users\20751\Desktop\异环\unpacked"
# 1) 读 status 旁边的串
raw=open(r"D:\qwork\libUnreal.so","rb").read()
for va in (0xa65a6a,):
    seg=raw[va:va+40]; s=seg.split(b"\x00")[0]
    print(f"libUnreal 0x{va:x}: {s!r}")
KW=[b"signature",b"Signature",b"getPackageInfo",b"GET_SIGNATURES",b"GET_SIGNING",
    b"MessageDigest",b"META-INF",b"checkSignature",b"verifySignature",b"PackageManager",
    b"getInstallerPackageName",b"collectCertificates",b"certificate",b"CERT.",b".RSA",
    b"signatures",b"signingInfo",b"SHA-256",b"SHA256",b"apkSig",b"__tpinfo",b"tpginf",
    b"AppSignature",b"getSignature",b"android.content.pm",b"checksum",b"crc32"]
# 2) 扫 SO
sodir=os.path.join(W,"so")
for so in sorted(os.listdir(sodir)):
    if not so.endswith(".so"): continue
    d=open(os.path.join(sodir,so),"rb").read()
    hits=[k.decode() for k in KW if k in d]
    if hits: print(f"\n### {so}: {hits}")
# 3) 扫 dex
for root,_,fs in os.walk(W):
    for f in fs:
        if f.endswith(".dex"):
            d=open(os.path.join(root,f),"rb").read()
            hits=[k.decode() for k in KW if k in d]
            if hits: print(f"\n### {os.path.join(root,f)}: {hits}")
