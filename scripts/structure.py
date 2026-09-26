# -*- coding: utf-8 -*-
"""按源码路径统计 libUnreal.so 的引擎模块构成 + 关键结构。"""
import re, collections
SO = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
d = open(SO, "rb").read()

# 抓形如 ./Runtime/.../Xxx.cpp  ./Plugins/.../Xxx.cpp  ../.../Xxx.h
PATH = re.compile(rb"(?:\.\.?/)+(?:Runtime|Plugins|Engine|Developer|Programs|Editor|Experimental|Core|Online|Sockets|GameplayAbilities|AIModule|Paper2D|PaperZD|Chaos|Interchange)/[ -~]{2,120}?\.(?:cpp|h|inl|cs)")

mods = collections.Counter()      # 顶层模块
mods2 = collections.Counter()     # 二级模块
seen = set()
for m in PATH.finditer(d):
    s = m.group().decode("latin1")
    if s in seen: continue
    seen.add(s)
    # 归一化：去掉开头 ./
    p = s.lstrip("./")
    parts = p.split("/")
    if len(parts) >= 2:
        mods[parts[0]] += 1                       # Runtime / Plugins / ...
        mods2["/".join(parts[:2])] += 1           # Runtime/Core, Plugins/Compression ...
    elif parts:
        mods[parts[0]] += 1

print(f"总路径串(去重): {len(seen)}\n")
print("== 顶层模块 ==")
for k, v in mods.most_common(): print(f"  {k:16s} {v}")
print("\n== 二级模块 Top 40 ==")
for k, v in mods2.most_common(40): print(f"  {k:40s} {v}")
