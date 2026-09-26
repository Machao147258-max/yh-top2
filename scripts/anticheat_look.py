# -*- coding: utf-8 -*-
"""1) GameActivity.java 的反调试上下文 2) libsecsdk JNI_OnLoad 反汇编。"""
import os, re, struct, capstone
# 1) GameActivity
p=r"C:\Users\20751\Desktop\异环\unpacked\java\sources\com\epicgames\unreal\GameActivity.java"
if os.path.exists(p):
    lines=open(p,encoding='utf-8',errors='ignore').read().splitlines()
    print("=== GameActivity.java 反调试/检测相关行 ===")
    for i,l in enumerate(lines):
        if any(k in l for k in ("Debugger","Debug.","isDebuggerConnected","System.exit","Process.kill","exit(","hottagames","Signature","signature")):
            print(f"  {i+1}: {l.strip()[:140]}")
else: print("GameActivity.java 不存在")
# 2) libsecsdk JNI_OnLoad
SO=r"C:\Users\20751\Desktop\异环\unpacked\so\libsecsdk.so"
from elftools.elf.elffile import ELFFile
raw=open(SO,"rb").read(); f=open(SO,"rb"); elf=ELFFile(f)
jni=[s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='JNI_OnLoad']
segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
def v2f(a):
    for v,o,fs in segs:
        if v<=a<v+fs: return o+(a-v)
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
if jni:
    va=jni[0]['st_value']; fo=v2f(va)
    print(f"\n=== libsecsdk JNI_OnLoad @0x{va:x} ===")
    for ins in md.disasm(raw[fo:fo+0x100], va):
        b=""
        if ins.mnemonic in("bl","b"):
            try: b=" ->0x%x"%int(ins.op_str.split('#')[-1],16)
            except: pass
        print(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}{b}")
f.close()
