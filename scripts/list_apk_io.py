# -*- coding: utf-8 -*-
"""列 APK 里 utoc/ucas/pak 相关条目。"""
import zipfile
APK=r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
z=zipfile.ZipFile(APK)
print("总条目", len(z.namelist()))
hits=[n for n in z.namelist() if any(k in n.lower() for k in ("ucas","utoc",".pak"))]
for n in hits:
    try: sz=z.getinfo(n).file_size
    except: sz=0
    print(f"  {sz:>12} {n}")
print("\nassets/ 下前 60:")
assets=[n for n in z.namelist() if n.startswith("assets/")]
for n in assets[:60]: print("  ",n)
print("assets 条目数:", len(assets))
