# -*- coding: utf-8 -*-
"""扫 jadx 反编译产物: 签名校验相关关键词在哪些类。"""
import os, re
BASE=r"C:\Users\20751\Desktop\异环\unpacked\java\sources"
KW=["checkSignature","verifySignature","getPackageInfo","GET_SIGNATURES","getSignatures",
    "PackageManager","MessageDigest","signatures","Signature","AppSignature","getSignature"]
hits={}
for root,_,fs in os.walk(BASE):
    for f in fs:
        if not f.endswith(".java"): continue
        p=os.path.join(root,f)
        try: t=open(p,encoding='utf-8',errors='ignore').read()
        except: continue
        found=[k for k in KW if k in t]
        if found:
            rel=os.path.relpath(p,BASE)
            hits[rel]=found
# 只显示含"校验"语义(排除纯 PackageManager 的)
sig=[(k,v) for k,v in hits.items() if any(x in v for x in ("checkSignature","verifySignature","getSignatures","GET_SIGNATURES","AppSignature","getSignature"))]
print(f"总命中类 {len(hits)}; 含签名校验语义 {len(sig)}")
print("\n=== 含签名校验语义的类 ===")
for k,v in sorted(sig)[:60]:
    print(f"  {k}: {','.join(v)}")
print("\n=== 其余(仅 PackageManager/MessageDigest 等) ===")
for k,v in sorted(hits.items())[:40]:
    if (k,v) not in sig: print(f"  {k}: {','.join(v)}")
