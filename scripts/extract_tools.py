# -*- coding: utf-8 -*-
"""解压 repak.zip/retoc.zip 到 tools/。"""
import zipfile, os
W=r"C:\Users\20751\Desktop\异环"
T=os.path.join(W,"tools"); os.makedirs(T, exist_ok=True)
for z in ("repak.zip","retoc.zip"):
    with zipfile.ZipFile(os.path.join(W,z)) as zf:
        zf.extractall(T)
print("tools/:", os.listdir(T))
for f in os.listdir(T):
    p=os.path.join(T,f); print(f"  {f}: {os.path.getsize(p) if os.path.isfile(p) else 'dir'}")
