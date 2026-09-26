# -*- coding: utf-8 -*-
"""普查 异环 未分析 SO：导出/JNI/特征串。"""
import os, struct

SO_DIR = r"C:\Users\20751\Desktop\异环\unpacked\so"
TARGETS = ["libsecsdk.so", "libthemis.so", "libclient.so", "libDfga_Catch.so"]

KW = [b"JNI_OnLoad", b"RegisterNatives", b"ptrace", b"frida", b"maps",
      b"Fake", b"debug", b"root", b"su", b"/proc/self", b"SSL_", b"curl",
      b"AES", b"SM4", b"SM2", b"RSA", b"MD5", b"SHA", b"sign", b"Sign",
      b"encrypt", b"decrypt", b"http", b"socket", b"dex", b"dalvik",
      b"Xposed", b"magisk", b"emulator", b"qemu", b"checksum", b"integrity"]

def elf_dynsym(path):
    d = open(path, "rb").read()
    # ELF64
    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i*e_shentsize
        nm, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", d, o)
        secs.append(dict(name=nm, typ=typ, off=off, size=size, link=link, entsize=entsize))
    shstr = secs[e_shstrndx]
    def sname(nm): 
        s = d[shstr["off"]+nm:]; return s[:s.find(b"\0")].decode("latin1")
    dynsym = next((s for s in secs if sname(s["name"]) == ".dynsym"), None)
    dynstr = next((s for s in secs if sname(s["name"]) == ".dynstr"), None)
    if not dynsym or not dynstr: return []
    def str_at(off):
        s = d[dynstr["off"]+off:]; return s[:s.find(b"\0")].decode("latin1")
    out = []
    n = dynsym["size"]//dynsym["entsize"]
    for i in range(n):
        o = dynsym["off"] + i*dynsym["entsize"]
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", d, o)
        if st_shndx == 0:  # UNDEF (import)
            continue
        nm = str_at(st_name)
        if nm:
            out.append(nm)
    return out

def main():
    for name in TARGETS:
        p = os.path.join(SO_DIR, name)
        d = open(p, "rb").read()
        exps = elf_dynsym(p)
        jni = [e for e in exps if e.startswith("Java_")]
        print(f"\n{'='*60}\n### {name}  ({len(d)/1024:.0f} KB)")
        print(f"  导出符号(定义): {len(exps)}   其中 Java_*: {len(jni)}")
        if jni:
            for e in jni[:40]:
                print(f"    {e}")
            if len(jni) > 40: print(f"    ... 还有 {len(jni)-40} 个")
        # 特征串
        print("  特征串:")
        for k in KW:
            c = d.count(k)
            if c:
                print(f"    {k.decode():14s}: {c}")

if __name__ == "__main__":
    main()
