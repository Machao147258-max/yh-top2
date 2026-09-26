# -*- coding: utf-8 -*-
import zipfile
APK=r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
z=zipfile.ZipFile(APK)
infos=sorted(z.infolist(), key=lambda i:-i.file_size)[:25]
print("APK 最大 25 个条目:")
for i in infos:
    print(f"  {i.file_size:>12} {i.filename}")
print("\nmain.obb.png:", [ (i.file_size) for i in z.infolist() if 'obb' in i.filename.lower() ])
print("\n含 .so 的:")
for i in z.infolist():
    if i.filename.endswith('.so'): print(f"  {i.file_size:>12} {i.filename}")
