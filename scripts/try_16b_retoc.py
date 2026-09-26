# -*- coding: utf-8 -*-
"""44 个 so 内 16B hex 串, 以 16B 直接试 retoc。"""
import subprocess, os, re
W=r"C:\Users\20751\Desktop\异环"
RETOC=os.path.join(W,"tools","retoc.exe")
UTOC=os.path.join(W,"unpacked","io","pakchunk0-Android_ASTC.utoc")
SO=os.path.join(W,"unpacked","so","libUnreal.so")
raw=open(SO,"rb").read()
strs=re.findall(rb"[\x20-\x7e]{6,200}", raw)
hexre=re.compile(rb"^[0-9a-fA-F]{32}$")
cands=sorted({x.decode() for x in strs if hexre.match(x)})
print(f"16B 候选 {len(cands)}")
ok=[]
for k in cands:
    try:
        r=subprocess.run([RETOC,"-a",k,"info",UTOC],capture_output=True,timeout=20)
        if r.returncode==0:
            print(f"*** 命中 {k} ***"); ok.append(k)
    except Exception: pass
# 也试 lower/upper
print("命中:", ok if ok else "无")
