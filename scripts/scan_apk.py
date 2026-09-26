# -*- coding: utf-8 -*-
"""列 APK 条目: assets + 可疑大文件/异常扩展名。"""
import zipfile,os
APK=r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
z=zipfile.ZipFile(APK)
infos=z.infolist()
print("总条目:",len(infos))
# assets
print("\n=== assets/ (前80) ===")
n=0
for i in infos:
    if i.filename.startswith("assets/") and not i.is_dir():
        print(f"  {i.file_size:>12} {i.filename}")
        n+=1
        if n>=80: break
# 非标准扩展名 / 大文件
print("\n=== 可疑(非 dex/so/arsc/png/jpg/ogg 且 >100KB) ===")
ok=(".dex",".so",".arsc",".png",".jpg",".jpeg",".webp",".ogg",".mp3",".mp4",".wav",".ttf",".otf",".json",".txt",".xml",".bin",".dat")
for i in sorted(infos,key=lambda x:-x.file_size)[:40]:
    if i.file_size>100000:
        print(f"  {i.file_size:>12} {i.filename}")
