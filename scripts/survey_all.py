# -*- coding: utf-8 -*-
"""四个未分析 SO 的综合普查：导出/JNI/依赖/检测/加密/网络/构造器。"""
import os, struct

SO_DIR = r"C:\Users\20751\Desktop\异环\unpacked\so"
FILES = ["libsecsdk.so", "libthemis.so", "libclient.so", "libDfga_Catch.so"]

CAT = {
    "检测-调试":   [b"ptrace", b"PTRACE", b"TracerPid", b"tracer", b"/proc/self/status"],
    "检测-Frida":  [b"frida", b"Frida", b"gadget", b"27042", b"27043", b"linjector", b"substrate", b"re.frida"],
    "检测-maps":   [b"/proc/self/maps", b"/proc/self/task", b"/proc/%d/maps"],
    "检测-root":   [b"/su", b"/system/bin/su", b"magisk", b"Magisk", b"superuser", b"/system/xbin", b"busybox"],
    "检测-Xposed": [b"Xposed", b"xposed", b"de.robv", b"epic."],
    "检测-模拟器": [b"qemu", b"QEMU", b"goldfish", b"ranchu", b"genymotion", b"vbox", b"bluestacks", b"emulator"],
    "加密":        [b"AES", b"aes", b"SM4", b"SM2", b"RSA", b"MD5", b"SHA1", b"SHA256", b"HMAC", b"EVP_", b"base64"],
    "网络":        [b"curl_", b"socket", b"connect", b"getaddrinfo", b"SSL_", b"http://", b"https://", b"send", b"recv"],
    "dex/vm":      [b"dex", b"Dex", b"DEX", b"dalvik", b"InterpretInternal", b"VMP", b"VmP"],
    "崩溃":        [b"signal", b"Crashpad", b"crashpad", b"nativeCrash", b"tombstone", b"SIGSEGV", b"backtrace"],
}

NOTABLE_IMPORTS = [b"ptrace", b"kill", b"fork", b"system", b"popen", b"dlopen", b"dlsym",
                   b"access", b"fopen", b"readlink", b"stat", b"socket", b"connect",
                   b"AES_", b"EVP_", b"SHA", b"MD5", b"curl_", b"SSL_",
                   b"__android_log_print", b"AAssetManager", b"open"]

def parse(path):
    d = open(path, "rb").read()
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
    def sn(nm):
        s = d[shstr["off"]+nm:]; return s[:s.find(b"\0")].decode("latin1")
    for s in secs: s["sname"] = sn(s["name"])
    dynsym = next((s for s in secs if s["sname"] == ".dynsym"), None)
    dynstr = next((s for s in secs if s["sname"] == ".dynstr"), None)
    exports, imports = [], []
    if dynsym and dynstr:
        def str_at(off):
            s = d[dynstr["off"]+off:]; return s[:s.find(b"\0")].decode("latin1")
        for i in range(dynsym["size"]//dynsym["entsize"]):
            o = dynsym["off"] + i*dynsym["entsize"]
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", d, o)
            nm = str_at(st_name)
            if not nm: continue
            (imports if st_shndx == 0 else exports).append(nm)
    initarr = next((s for s in secs if s["sname"] == ".init_array"), None)
    ninit = initarr["size"]//8 if initarr else 0
    return d, exports, imports, ninit

def main():
    for name in FILES:
        d, exp, imp, ninit = parse(os.path.join(SO_DIR, name))
        jni = [e for e in exp if e.startswith("Java_")]
        print(f"\n{'='*72}\n### {name}   ({len(d)/1024:.0f} KB)")
        print(f"  导出={len(exp)}  Java_*={len(jni)}  导入={len(imp)}  init_array={ninit}")
        print(f"  JNI_OnLoad={'有' if b'JNI_OnLoad' in d else '无'}   RegisterNatives={'有' if b'RegisterNatives' in d else '无'}")
        if jni:
            print("  JNI 导出:")
            for e in jni[:20]: print("     ", e)
        # 依赖库
        needed = [i for i in imp if i.endswith(".so")]
        if needed: print("  NEEDED:", ", ".join(needed))
        # 重点关注导入
        ni = [i for i in imp if any(k.decode() in i for k in NOTABLE_IMPORTS)]
        if ni: print("  关键导入:", ", ".join(sorted(set(ni))))
        # 分类特征
        print("  特征面:")
        for cat, kws in CAT.items():
            hit = {}
            for k in kws:
                c = d.count(k)
                if c: hit[k.decode()] = c
            if hit:
                print(f"    [{cat}] " + ", ".join(f"{k}×{v}" for k,v in sorted(hit.items(), key=lambda x:-x[1])[:8]))

if __name__ == "__main__":
    main()
