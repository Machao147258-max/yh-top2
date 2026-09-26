# -*- coding: utf-8 -*-
"""打印检测串命中处的上下文, 辨真假阳性。"""
import os,re
W=r"C:\Users\20751\Desktop\异环\unpacked\so"
SOS=["libsecsdk.so","libmxcore.so","libUnreal.so","libDfga_Catch.so","libclient.so","libthemis.so"]
KEYS=[b"gum",b"/su",b"xposed",b"/proc/self/status",b"TracerPid",b"frida",b"magisk",b"qemu",b"goldfish",b"ranchu"]
def ctx(raw,i,n=48):
    a=max(0,i-n); b=min(len(raw),i+n)
    seg=raw[a:b]
    return seg.decode('latin1','replace').replace('\x00','.')
for so in SOS:
    p=os.path.join(W,so)
    if not os.path.exists(p): continue
    raw=open(p,"rb").read()
    print(f"\n===== {so} =====")
    for kw in KEYS:
        i=raw.find(kw); cnt=raw.count(kw)
        if i!=-1:
            print(f"  '{kw.decode()}' x{cnt} 首现@0x{i:x}: ...{ctx(raw,i)}...")
