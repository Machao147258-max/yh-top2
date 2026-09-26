# -*- coding: utf-8 -*-
"""查 libUnreal.so 里 Oodle 的痕迹: 是完整实现还是外部库外壳。"""
import re
SO=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so"
raw=open(SO,"rb").read()
for kw in [b"oo2core", b"liboo2", b"OodleLZ_Decompress", b"OodleLZ_Compress",
           b"Kraken", b"Mermaid", b"Selkie", b"Leviathan", b"OO2", b"OodleCore",
           b"oodle", b"lzdecod", b"tdecompress"]:
    i=0; hits=[]
    while True:
        i=raw.find(kw,i)
        if i<0: break
        hits.append(i); i+=1
    if hits:
        print(f"\n{kw.decode(errors='replace'):22s} {len(hits)} 处:")
        for h in hits[:6]:
            c=raw[max(0,h-24):h+48]
            c=bytes(x if 32<=x<127 else 46 for x in c).decode()
            print(f"   0x{h:x}: {c}")
    else:
        print(f"{kw.decode(errors='replace'):22s} 0 处")
