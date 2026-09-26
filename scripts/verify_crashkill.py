# -*- coding: utf-8 -*-
"""查会闪退的: 各 SO 的 exit/abort/kill 导入 + 关键检测串偏移。"""
import os
from elftools.elf.elffile import ELFFile
W=r"C:\Users\20751\Desktop\异环\unpacked\so"
SOS=["libthemis.so","libsecsdk.so","libmxcore.so","libUnreal.so","libDfga_Catch.so","libclient.so"]
KILL=["exit","_exit","abort","__assert2","kill","raise","pthread_kill","syscall","_ZSt9terminatev",
      "std::terminate","__cxa_throw","longjmp","siglongjmp","_Unwind_Resume","__stack_chk_fail"]
KEYS=["gum-js","gum","/su","xposed","/proc/self/status","TracerPid","frida","magisk","qemu","goldfish","ranchu"]
def alloff(raw,kw):
    out=[];i=raw.find(kw)
    while i!=-1 and len(out)<4: out.append(hex(i)); i=raw.find(kw,i+1)
    return out
for so in SOS:
    p=os.path.join(W,so)
    if not os.path.exists(p): continue
    raw=open(p,"rb").read()
    f=open(p,"rb"); elf=ELFFile(f); dyn=elf.get_section_by_name('.dynsym')
    imports=set(s.name for s in dyn.iter_symbols() if s.name and s['st_shndx']=='SHN_UNDEF')
    f.close()
    kills=[k for k in KILL if k in imports]
    print(f"\n### {so}")
    print("  ★可终止进程的导入:", kills or "无")
    for kw in KEYS:
        o=alloff(raw,kw.encode())
        if o: print(f"    '{kw}' @ {o}")
