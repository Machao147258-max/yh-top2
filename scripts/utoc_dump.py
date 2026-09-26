# -*- coding: utf-8 -*-
"""看 io/ 文件大小 + utoc(IoStore) 头部结构。"""
import os, struct, glob
IO=r"C:\Users\20751\Desktop\异环\unpacked\io"
for p in sorted(glob.glob(os.path.join(IO,"*"))):
    print(f"{os.path.basename(p):40s} {os.path.getsize(p):>12,} 字节")
print()
for name in ("global.utoc","pakchunk0-Android_ASTC.utoc"):
    p=os.path.join(IO,name)
    if not os.path.exists(p): continue
    d=open(p,"rb").read()
    print(f"\n===== {name} ({len(d)} 字节) 头 96B =====")
    for i in range(0,96,16):
        print(f"+{i:04x}: " + " ".join(f"{b:02x}" for b in d[i:i+16]) + "  " +
              "".join(chr(b) if 32<=b<127 else "." for b in d[i:i+16]))
    # IoStore TOC header: magic "-==--==--==--==-" (16 bytes) 
    print("  前16字节:", d[:16], "  (IoStore magic = -==--==--==--==-)")
