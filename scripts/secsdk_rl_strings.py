# -*- coding: utf-8 -*-
"""在 libsecsdk 里找 rL 相关: Java方法名(getStaticFO/showRiskMessage/getFieldSCDesc/doTypeShort)
   + JNI 签名 + rL 字符串 + JNINativeMethod 表候选。"""
import re
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
for kw in (b"rL",b"getStaticFO",b"showRiskMessage",b"getFieldSCDesc",b"doTypeShort",
           b"Ljava/lang/Object;",b"([Ljava/lang/Object;)Ljava/lang/Object;",
           b"sdkwrapper",b"netease",b"Utils",b"getLooper",b"Looper",b"Toast",
           b"Signature",b"isDebuggerConnected",b"getPackageInfo",b"MessageDigest"):
    idxs=[m.start() for m in re.finditer(re.escape(kw), raw)]
    if idxs:
        print(f"{kw!r}: {len(idxs)} 处 -> {[hex(i) for i in idxs[:6]]}")
        for i in idxs[:3]:
            seg=raw[max(0,i-16):i+len(kw)+24]
            print(f"    0x{i:x}: {seg!r}")
    else:
        print(f"{kw!r}: 无")
f.close()
