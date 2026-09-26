# -*- coding: utf-8 -*-
"""核实 utoc/pak 魔数在哪些 SO 里出现（判断 IoStore 读取器位置）。"""
import os
SO_DIR = r"C:\Users\20751\Desktop\异环\unpacked\so"
PATS = {
    "utoc_magic_16": bytes.fromhex("2D3D3D2D2D3D3D2D2D3D3D2D2D3D3D2D"),
    "utoc_magic_8":  bytes.fromhex("2D3D3D2D2D3D3D2D"),
    "utoc_magic_4":  bytes.fromhex("2D3D3D2D"),
    "pak_magic_LE":  bytes.fromhex("E1126F5A"),
    "IoStore":       b"IoStore",
    "TocHeader":     b"TocHeader",
    "DirectoryIndex":b"DirectoryIndex",
    "CompressionBlock": b"CompressionBlock",
}
for name in sorted(os.listdir(SO_DIR)):
    if not name.endswith(".so"): continue
    d = open(os.path.join(SO_DIR, name), "rb").read()
    hits = {k: d.count(v) for k, v in PATS.items() if d.count(v)}
    if hits:
        print(f"\n### {name} ({len(d)/1024/1024:.1f} MB)")
        for k, v in hits.items():
            print(f"    {k}: {v}")
