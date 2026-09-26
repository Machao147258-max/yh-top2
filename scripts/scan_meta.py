# -*- coding: utf-8 -*-
"""找【游戏自身】的 APK 签名校验: META-INF / 自己包名 / CERT.RSA。"""
import os
BASE=r"C:\Users\20751\Desktop\异环\unpacked\java\sources"
KW=["META-INF","CERT.RSA","hottagames","yh.laohu","getPackageName","getApplicationInfo",
    "getEntry(","ZipFile","getPackageArchiveInfo","/classes.dex","hookdetect","rootdetect",
    "isRooted","checkRoot","emulator","isEmulator","isDebuggerConnected","Debug.isDebuggerConnected"]
hits={}
for root,_,fs in os.walk(BASE):
    for f in fs:
        if not f.endswith(".java"): continue
        p=os.path.join(root,f)
        try: t=open(p,encoding='utf-8',errors='ignore').read()
        except: continue
        found=[k for k in KW if k in t]
        if found: hits[os.path.relpath(p,BASE)]=found
print(f"命中 {len(hits)} 个类:")
for k,v in sorted(hits.items())[:80]:
    print(f"  {k}: {','.join(v)}")
