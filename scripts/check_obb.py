# -*- coding: utf-8 -*-
"""看 main.obb.png 真实格式(前 64B) + 是否 ZIP。"""
import zipfile, struct
APK=r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
z=zipfile.ZipFile(APK)
with z.open("assets/main.obb.png") as f:
    head=f.read(64)
print("前64B hex:", head.hex())
print("前16B ascii:", head[:16])
# PNG?
print("PNG magic:", head[:8]==b"\x89PNG\r\n\x1a\n")
print("ZIP magic:", head[:4]==b"PK\x03\x04")
# 末尾(找 EOCD)
info=z.getinfo("assets/main.obb.png")
print("entry compress_type:", info.compress_type, "size", info.file_size)
# OBB 名/版本 via zip?  尝试当作独立 zip 打开(需解出)。先看是否含 'obb'
print("OBB 特征(前若干字节含 PK 或 gzip):", head[:2])
