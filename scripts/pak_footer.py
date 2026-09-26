# -*- coding: utf-8 -*-
"""解析 UE pak 尾部 FPakInfo：魔数/版本/IndexOffset/IndexSize/IndexHash/加密标志。"""
import struct, hashlib, glob, os
PAKS = sorted(set(glob.glob(r"C:\Users\20751\Desktop\异环\unpacked\**\*.pak", recursive=True)))
MAGIC = 0x5A6F12E1
for PAK in PAKS:
    d = open(PAK, "rb").read(); n = len(d)
    print(f"\n===== {os.path.basename(PAK)}  ({n/1e6:.1f} MB) =====")
    tail = d[-2048:] if n > 2048 else d
    pos = tail.rfind(struct.pack("<I", MAGIC))
    if pos < 0:
        i=0; allp=[]
        while True:
            i = d.find(struct.pack("<I",MAGIC), i)
            if i<0: break
            allp.append(i); i+=1
        # 只显示靠后的
        print("  尾部2048无魔数; 全文件魔数位置:", [hex(x) for x in allp[-8:]])
        if not allp: continue
        fo = allp[-1]
    else:
        fo = n - len(tail) + pos
    print(f"  魔数 @ 0x{fo:x} (距末尾 {n-fo})")
    ver = struct.unpack_from("<i", d, fo+4)[0]
    idx_off = struct.unpack_from("<q", d, fo+8)[0]
    idx_sz  = struct.unpack_from("<q", d, fo+16)[0]
    idx_hash= d[fo+24:fo+44]
    print(f"  version={ver}  IndexOffset=0x{idx_off:x}  IndexSize=0x{idx_sz:x}({idx_sz})")
    print(f"  IndexHash={idx_hash.hex()}")
    p = fo+44
    if ver >= 7:
        guid=d[p:p+16]; p+=16; print(f"  EncryptionKeyGuid={guid.hex()}")
    if ver >= 8:
        print(f"  bEncryptedIndex={d[p]}"); p+=1
    if 0<idx_off<n and idx_sz>0:
        seg = d[idx_off:idx_off+idx_sz]
        hh = hashlib.sha1(seg).hexdigest()
        print(f"  SHA1(IndexOffset处)={hh}  匹配IndexHash={hh==idx_hash.hex()}")
        print(f"  该处前16字节: {seg[:16].hex()}")
