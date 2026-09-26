# -*- coding: utf-8 -*-
"""扫描异环所有 SO，定位与 Oodle 压缩有关的库。"""
import os, re

SO_DIR = r"C:\Users\20751\Desktop\异环\unpacked\so"

# Oodle / oo2core 相关特征（区分大小写地找几组）
PATTERNS = [
    b"oo2core", b"OO2CORE", b"Oodle", b"oodle", b"OODLE",
    b"OodleLZ", b"OO_SDK", b"oo2_",
    b"Kraken", b"Mermaid", b"Selkie", b"Leviathan",   # Oodle 算法族
    b"OodleDecompress", b"OodleLZ_Decompress", b"OodleLZ_Compress",
    b"RAD Games", b"RADGameTools", b"radgametools",
    b"CompressBlock", b"DecompressBlock",
]

def scan(path):
    with open(path, "rb") as f:
        data = f.read()
    hits = {}
    for p in PATTERNS:
        n = data.count(p)
        if n:
            hits[p.decode("latin1")] = n
    return hits

def main():
    rows = []
    for name in sorted(os.listdir(SO_DIR)):
        if not name.endswith(".so"):
            continue
        path = os.path.join(SO_DIR, name)
        hits = scan(path)
        rows.append((name, os.path.getsize(path), hits))

    print("=" * 70)
    for name, size, hits in rows:
        tag = "  <== OODLE!" if hits else ""
        print(f"\n### {name}  ({size/1024/1024:.2f} MB){tag}")
        if hits:
            for k, v in sorted(hits.items(), key=lambda x: -x[1]):
                print(f"    {k!r}: {v}")
        else:
            print("    (无 Oodle 特征)")
    print("\n" + "=" * 70)
    print("含 Oodle 特征的库：", [n for n, s, h in rows if h])

if __name__ == "__main__":
    main()
