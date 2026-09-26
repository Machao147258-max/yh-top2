# -*- coding: utf-8 -*-
"""列出 repak.zip / retoc.zip 内容。"""
import zipfile, os
W=r"C:\Users\20751\Desktop\异环"
for z in ("repak.zip","retoc.zip"):
    p=os.path.join(W,z)
    print(f"\n===== {z} ({os.path.getsize(p)}B) =====")
    try:
        with zipfile.ZipFile(p) as zf:
            for i in zf.infolist()[:40]:
                print(f"  {i.file_size:>12} {i.filename}")
    except Exception as e:
        print("  列表失败:",e)
