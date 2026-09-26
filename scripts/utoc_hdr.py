# -*- coding: utf-8 -*-
"""解析 IoStore .utoc 头部, 找 EncryptionKeyGuid / ContainerId。"""
import struct, os
IO=r"C:\Users\20751\Desktop\异环\unpacked\io"
for name in ("global.utoc","pakchunk0-Android_ASTC.utoc","pakchunk1-Android_ASTC.utoc"):
    p=os.path.join(IO,name)
    if not os.path.exists(p): continue
    d=open(p,"rb").read()
    print(f"\n===== {name} ({len(d)}B) =====")
    if d[:16]!=b"-==--==--==--==-": print("  非 IoStore"); continue
    print(f"  version={d[16]}")
    vals=struct.unpack_from("<7I", d, 20)
    names=["tocHeaderSize","tocEntryCount","tocCompBlkEntryCount","tocCompBlkEntrySize",
           "compMethodNameCount","compMethodNameLen","compBlockSize"]
    for n,v in zip(names,vals): print(f"  {n}={v}")
    print(f"  [48:64] ContainerId? = {d[48:64].hex()}")
    print(f"  [64:80] KeyGuid?     = {d[64:80].hex()}")
    print(f"  [16:112] hex: {d[16:112].hex()}")
    for off in range(48, min(len(d),256), 16):
        seg=d[off:off+16]
        if seg!=b"\x00"*16 and seg!=b"\xff"*16:
            print(f"   nonzero16 @+{off}: {seg.hex()}")
