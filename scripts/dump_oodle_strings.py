# -*- coding: utf-8 -*-
"""从 libUnreal.so 提取所有 Oodle / oo2core 相关可打印串（带文件偏移），定位解压器。"""
import re

SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
KEY = re.compile(rb"[ -~]{4,}")

# 抓含这些关键字的串
WANT = ["oodle", "oo2", "kraken", "mermaid", "selkie", "leviathan",
        "radgame", "rad game", "OodleLZ", "decompress", "Decompress"]

def main():
    with open(SO, "rb") as f:
        data = f.read()
    print(f"文件: {SO}  ({len(data)/1024/1024:.1f} MB)\n")

    seen = set()
    out = []
    for m in KEY.finditer(data):
        s = m.group()
        if any(w.encode() in s or w.lower().encode() in s.lower() for w in WANT):
            # 过滤明显不相干的（比如含 'oodle' 但其实是别的）
            out.append((m.start(), s.decode("latin1")))

    # 去重（同串只留第一处）
    uniq = []
    for off, s in out:
        if s in seen:
            continue
        seen.add(s)
        uniq.append((off, s))

    print(f"命中 {len(out)} 处，去重后 {len(uniq)} 条：\n")
    for off, s in uniq:
        print(f"  0x{off:08x}  {s[:160]}")

if __name__ == "__main__":
    main()
