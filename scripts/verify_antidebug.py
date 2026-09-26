# -*- coding: utf-8 -*-
"""核查反调试/反检测 是否真实存在: 查字符串 + 导入。"""
import os, re
from elftools.elf.elffile import ELFFile
W=r"C:\Users\20751\Desktop\异环\unpacked\so"
SOS=["libthemis.so","libsecsdk.so","libmxcore.so","libUnreal.so","libclient.so","libDfga_Catch.so"]
STR=["TracerPid","/proc/self/status","/proc/self/maps","/proc/","ptrace","PR_SET_DUMPABLE",
     "PTRACER","prctl","debugger","frida","gum-js","gum","magisk","qemu","goldfish","ranchu",
     "ro.debuggable","ro.kernel.qemu","/su","xposed","TracerPid:","IsDebuggerPresent"]
IMP=["ptrace","prctl","ioctl","__system_property_get","readlink","memmem","dl_iterate_phdr"]
for so in SOS:
    p=os.path.join(W,so)
    if not os.path.exists(p): print(f"\n### {so} 不存在"); continue
    raw=open(p,"rb").read()
    f=open(p,"rb"); elf=ELFFile(f)
    dyn=elf.get_section_by_name('.dynsym')
    imports=set()
    for s in dyn.iter_symbols():
        if s.name and s['st_shndx']=='SHN_UNDEF': imports.add(s.name)
    f.close()
    print(f"\n### {so} ({len(raw)}B)")
    print("  导入命中:", [x for x in IMP if x in imports] or "无")
    hits=[k for k in STR if k.encode() in raw]
    print("  字符串命中:", hits or "无")
