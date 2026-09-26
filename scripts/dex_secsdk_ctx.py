# -*- coding: utf-8 -*-
"""classes.dex @0xc21e8 周边串 -> 找加载 secsdk 的类。"""
import re
d=open(r"C:\Users\20751\Desktop\异环\unpacked\dex\classes.dex","rb").read()
lo,hi=0xc2100,0xc2400
seg=d[lo:hi]
print("=== 周边可读串 ===")
for m in re.finditer(rb"[\x20-\x7e]{4,}", seg):
    print(f"  0x{lo+m.start():x}: {m.group().decode('latin1')}")
