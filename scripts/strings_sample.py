# -*- coding: utf-8 -*-
"""抽取 SO 里"有信息量"的字符串：路径/URL/版本/厂商。"""
import os, re
SO_DIR = r"C:\Users\20751\Desktop\异环\unpacked\so"
FILES = ["libsecsdk.so", "libthemis.so", "libclient.so", "libDfga_Catch.so"]

STR = re.compile(rb"[ -~]{6,}")
# 关注：路径、URL、版本、厂商关键字
FOCUS = re.compile(rb"(\.cpp|\.c\b|\.h\b|/|http|www\.|\.com|version|Version|VERSION|"
                   rb"taptap|TapTap|crash|Crash|sign|Sign|crypt|Crypt|key|Key|"
                   rb"dex|Dex|DEX|vm|VM|VMP|anti|Anti|root|Root|hook|Hook|"
                   rb"emulator|Emulator|magisk|Magisk|xposed|Xposed|frida|Frida)", re.I)

def main():
    for name in FILES:
        p = os.path.join(SO_DIR, name)
        d = open(p, "rb").read()
        seen = set(); out = []
        for m in STR.finditer(d):
            s = m.group().decode("latin1")
            if FOCUS.search(m.group()) and s not in seen:
                seen.add(s); out.append(s)
        print(f"\n{'='*70}\n### {name}  (命中 {len(out)} 条，显示前 60)")
        for s in out[:60]:
            print("   ", s[:120])

if __name__ == "__main__":
    main()
