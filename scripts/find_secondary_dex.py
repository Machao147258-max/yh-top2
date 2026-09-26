# -*- coding: utf-8 -*-
"""只看 dex/ 目录: 二级DEX + secsdk串上下文。"""
import os, re
ROOT=r"C:\Users\20751\Desktop\异环"
DEXDIR=os.path.join(ROOT,"unpacked","dex")
print("=== dex/ 目录文件 magic ===")
for f in sorted(os.listdir(DEXDIR)):
    p=os.path.join(DEXDIR,f); d=open(p,"rb").read()
    mag=d[:8]
    extra=[m for m in (b"dex\n035",b"dex\n036",b"dex\n037",b"dex\n038",b"dex\n039") if d.find(m)>8]
    print(f"  {f}: {len(d)}字节 magic={mag!r} 内层DEX={len(extra)}")
print("\n=== classes.dex/2 里 secsdk/security 上下文 ===")
for name in ("classes.dex","classes2.dex"):
    p=os.path.join(DEXDIR,name); d=open(p,"rb").read()
    for kw in (b"secsdk",b"SecuritySdk",b"SecSdk",b"sec_sdk",b"libsec",b"security"):
        for m in re.finditer(re.escape(kw), d):
            a=m.start()
            while a>0 and 0x20<=d[a-1]<0x7f: a-=1
            b=m.start()+len(kw)
            while b<len(d) and 0x20<=d[b]<0x7f: b+=1
            print(f"  {name} 0x{m.start():x}: {d[a:b][:90]!r}")
# 找 classes.dex 里字符串表里所有含 sec/sdk/sec 的类名
print("\n=== classes.dex 里类名含 sec/Security/sdk ===")
d=open(os.path.join(DEXDIR,"classes.dex"),"rb").read()
for m in re.finditer(rb"L[a-zA-Z0-9_/$]*(?:[Ss]ec|[Ss]dk|Security)[a-zA-Z0-9_/$]*;", d):
    s=m.group().decode('latin1')
    if 'secsdk' in s.lower() or 'security' in s.lower(): print("  ",s[:110])
