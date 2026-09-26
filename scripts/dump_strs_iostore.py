# -*- coding: utf-8 -*-
"""读 sub_2545C8C 引用的串。"""
raw=open(r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so","rb").read()
def rd(va,n):
    d=raw[va:va+n]
    return d.decode('latin1',errors='replace')
for va,n in [(0xb40659,15),(0xb40785,14),(0xb9efe7,7),(0xc00299,9),(0xc510ee,8),(0xbf0d43,0x13)]:
    print(f"0x{va:x} (len{n}): {rd(va,n)!r}")
