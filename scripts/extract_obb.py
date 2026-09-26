# -*- coding: utf-8 -*-
"""把 main.obb.png 解到 disk，再列里面的 utoc/ucas/pak。"""
import zipfile, os, shutil, sys
APK=r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
OUT=r"C:\Users\20751\Desktop\异环\unpacked\obb\main.obb"
os.makedirs(os.path.dirname(OUT), exist_ok=True)
if not os.path.exists(OUT) or os.path.getsize(OUT)!=1009945025:
    print("解出 main.obb ...", flush=True)
    z=zipfile.ZipFile(APK)
    with z.open("assets/main.obb.png") as src, open(OUT,"wb") as dst:
        shutil.copyfileobj(src, dst, 64*1024*1024)
    print("done", os.path.getsize(OUT), flush=True)
# 当作 zip 列
oz=zipfile.ZipFile(OUT)
names=oz.namelist()
print("OBB 条目数:", len(names))
print("\n=== utoc/ucas/pak ===")
for n in names:
    if any(k in n.lower() for k in ("ucas","utoc",".pak")):
        print(f"  {oz.getinfo(n).file_size:>12} {n}")
print("\n=== 顶层目录 ===")
tops=sorted(set(n.split('/')[0] for n in names))
print(tops[:40])
