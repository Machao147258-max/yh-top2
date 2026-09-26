# -*- coding: utf-8 -*-
"""把 SO + rootfs 复制到纯英文目录 D:\qwork，供 Qiling 使用。"""
import os, shutil, time
t0=time.time()
D=r"D:\qwork"
os.makedirs(D, exist_ok=True)

srcs = [
    (r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so", r"D:\qwork\libUnreal.so", "file"),
    (r"D:\逆向工具\qiling\rootfs\rootfs-master\arm64_android", r"D:\qwork\rootfs\arm64_android", "dir"),
]
for src, dst, kind in srcs:
    if not os.path.exists(src):
        print(f"[skip] 源不存在: {src}"); continue
    if os.path.exists(dst):
        print(f"[skip] 已存在: {dst}"); continue
    if kind=="file":
        shutil.copy2(src, dst); print(f"[copy file] {src} -> {dst}")
    else:
        shutil.copytree(src, dst); print(f"[copy dir ] {src} -> {dst}")
print(f"done in {time.time()-t0:.1f}s")
print("D:\\qwork 内容:", os.listdir(D))
