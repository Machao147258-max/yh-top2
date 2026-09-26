# -*- coding: utf-8 -*-
"""校验 libsecsdk.so 里到底有没有这些串(对比法)。"""
import re, os
for SO in [r"D:\qwork\libsecsdk.so"]:
    print(SO, "size=", os.path.getsize(SO))
    data=open(SO,"rb").read()
    for kw in [b"intValue", b"longValue", b"java/lang", b"Utils", b"loadClass",
               b"getClassLoader", b"ClassLoader", b"com/netease/nis", b"showRisk",
               b"dex", b"native", b"JNI_OnLoad"]:
        c=data.count(kw)
        print(f"  {kw!r}: {c}")
    # 打印所有长度>=6的可见ASCII串里含 'oad'/'lass'/'Dex' 的
    print("  --- 含 lass/Dex/nis 的可读串 ---")
    for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
        s=m.group()
        if any(k in s for k in (b"lass", b"Dex", b"nis", b"ssLoader", b"vmp", b"VMP")):
            print("   ", hex(m.start()), s[:80])
