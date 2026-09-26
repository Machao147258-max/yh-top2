# -*- coding: utf-8 -*-
"""找谁加载 libsecsdk / 引用 secsdk 的 Java 类。"""
import os
BASE=r"C:\Users\20751\Desktop\异环\unpacked\java\sources"
KW=["secsdk","secsdk.so","loadLibrary","SecuritySdk","secpkg","libsec"]
hits={}
for root,_,fs in os.walk(BASE):
    for f in fs:
        if not f.endswith(".java"): continue
        p=os.path.join(root,f)
        try: t=open(p,encoding='utf-8',errors='ignore').read()
        except: continue
        found=[k for k in KW if k in t]
        if found: hits[os.path.relpath(p,BASE)]=found
for k,v in sorted(hits.items()):
    print(f"  {k}: {v}")
print(f"\n共 {len(hits)} 类")
