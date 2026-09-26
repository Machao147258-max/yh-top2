"""判定 pak/utoc 的加密与压缩状态（只输出结论，不 dump 大块数据）。"""
import struct, os, sys, zlib
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PAKD = r"C:\Users\20751\Desktop\异环\unpacked\pak"
UTOCD = r"C:\Users\20751\Desktop\异环\unpacked\utoc"
OUT = r"C:\Users\20751\Desktop\异环\reports\11_utoc_pak状态.txt"
lines = []
def log(s):
    print(s); lines.append(s)

PAK_MAGIC = 0x5A6F12E1

log("=== PAK FPakInfo 解析 ===")
for fn in sorted(os.listdir(PAKD)):
    if not fn.endswith(".pak"): continue
    p = os.path.join(PAKD, fn)
    d = open(p, "rb").read()
    pos = d.rfind(struct.pack("<I", PAK_MAGIC))
    log("\n-- %s (%d B) magic@%d" % (fn, len(d), pos))
    if pos < 0:
        log("   无 magic"); continue
    o = pos + 4
    ver = struct.unpack_from("<i", d, o)[0]; o += 4
    idx_off = struct.unpack_from("<q", d, o)[0]; o += 8
    idx_size = struct.unpack_from("<q", d, o)[0]; o += 8
    idx_hash = d[o:o+20]; o += 20
    b_enc = None
    if ver >= 4:
        b_enc = d[o]; o += 1
    enc_guid = None
    if ver >= 8:
        enc_guid = d[o:o+16]; o += 16
    log("   Version=%d IndexOffset=%d IndexSize=%d" % (ver, idx_off, idx_size))
    log("   bEncryptedIndex=%s  EncryptionKeyGuid=%s" % (b_enc, enc_guid.hex() if enc_guid else None))
    # 索引区熵
    idx = d[idx_off:idx_off+min(idx_size, 4096)]
    if idx:
        from collections import Counter
        import math
        c = Counter(idx); n = len(idx)
        ent = -sum((v/n)*math.log2(v/n) for v in c.values())
        log("   索引区前4KB 熵=%.2f  前16B=%s" % (ent, idx[:16].hex(" ")))
        # 尝试 zlib
        try:
            zlib.decompress(idx); log("   zlib 可解")
        except Exception:
            log("   zlib 不可解(加密/Oodle)")

log("\n=== UTOC 头 (ContainerFlags / 压缩方法) ===")
for fn in sorted(os.listdir(UTOCD)):
    if not fn.endswith(".utoc"): continue
    d = open(os.path.join(UTOCD, fn), "rb").read()
    # 头字段
    ver, hdr = struct.unpack_from("<II", d, 16)
    entrycnt = struct.unpack_from("<I", d, 24)[0]
    mcnt, mlen = struct.unpack_from("<II", d, 40)
    log("\n-- %s ver=%d hdr=%d entries=%d methodNameCount=%d" % (fn, ver, hdr, entrycnt, mcnt))
    # 压缩方法名紧跟头
    names = d[hdr:hdr+mcnt*mlen]
    log("   压缩方法名: %r" % names.rstrip(b"\x00"))
    # ContainerFlags 在头里 (通常是 u8, 在 ContainerId 之后)
    # FIoStoreTocHeader: ... Pad(4) ContainerId(8) ContainerHash?(32?) ... 
    # 直接扫头部找 flags 字节
    log("   头 hex: %s" % d[:hdr].hex(" "))
    # 解压目录索引 (Oodle 检测)
    dirsz = struct.unpack_from("<I", d, 56)[0] if hdr >= 60 else 0
    idx_off = len(d) - dirsz
    idx = d[idx_off:idx_off+min(dirsz, 64)]
    log("   目录索引 offset=%d size=%d 前16B=%s" % (idx_off, dirsz, idx[:16].hex(" ")))

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("\nwrote", OUT)
