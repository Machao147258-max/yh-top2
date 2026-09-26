# -*- coding: utf-8 -*-
"""libsecsdk 需要啥: DT_NEEDED + 5个dex里谁引用 secsdk。"""
import os, re, glob
from elftools.elf.elffile import ELFFile
# 1) ELF 依赖
SO=r"C:\Users\20751\Desktop\异环\unpacked\so\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
needed=[t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags() if t.entry.d_tag=='DT_NEEDED']
def strtab(i): return elf.get_section_by_name('.dynstr').get_string(i)
print("DT_NEEDED:", [strtab(n) for n in needed])
print("SONAME:", [strtab(t.entry.d_val) for t in elf.get_section_by_name('.dynamic').iter_tags() if t.entry.d_tag=='DT_SONAME'])
f.close()
# 2) dex 引用 secsdk
print("\n=== dex 里引用 secsdk ===")
for p in glob.glob(r"C:\Users\20751\Desktop\异环\unpacked\dex\*.dex"):
    d=open(p,"rb").read()
    idxs=[m.start() for m in re.finditer(rb"secsdk", d)]
    idxs+=[m.start() for m in re.finditer(rb"[Ss]ecsdk", d)]
    if idxs:
        for i in idxs[:5]:
            a=i
            while a>0 and 0x20<=d[a-1]<0x7f: a-=1
            b=i+6
            while b<len(d) and 0x20<=d[b]<0x7f: b+=1
            print(f"  {os.path.basename(p)} 0x{i:x}: {d[a:b][:80]!r}")
print("\n=== dex 里 'SecuritySdk'/'loadLibrary(sec' ===")
for p in glob.glob(r"C:\Users\20751\Desktop\异环\unpacked\dex\*.dex"):
    d=open(p,"rb").read()
    for kw in (b"secsdk",b"SecuritySdk.so",b"libsec"):
        if kw in d: print(f"  {os.path.basename(p)}: 含 {kw}")
