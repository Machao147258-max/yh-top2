"""提取 OBB 内的 .pak，解析 UE FPakInfo 索引；并读 utoc 压缩方法名 + ContainerFlags。"""
import zipfile, struct, os, sys, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

APK = r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
OUTP = r"C:\Users\20751\Desktop\异环\unpacked\pak"
OUTU = r"C:\Users\20751\Desktop\异环\unpacked\utoc"
os.makedirs(OUTP, exist_ok=True)

z = zipfile.ZipFile(APK)
obb_size = z.getinfo("assets/main.obb.png").file_size
TAIL = 512 * 1024
s = z.open("assets/main.obb.png"); s.seek(obb_size - TAIL); tail = s.read(); s.close()
eocd = tail.rfind(b"PK\x05\x06"); cd_end = eocd
entries = []
i = 0
while i < cd_end - 46:
    if struct.unpack("<I", tail[i:i+4])[0] != 0x02014b50:
        i += 1; continue
    v = struct.unpack("<HHHHHHIIIHHHHHII", tail[i+4:i+46])
    (vmade, vneed, flags, method, mt, md, crc, csize, usize, nlen, elen, clen2, disk, intattr, extattr, locoff) = v
    name = tail[i+46:i+46+nlen].decode("utf8", "replace")
    x = i + 46 + nlen; ex = tail[x:x+elen]; k = 0
    while k + 4 <= len(ex):
        hdr, sz2 = struct.unpack("<HH", ex[k:k+4])
        if hdr == 0x0001:
            vals = ex[k+4:k+4+sz2]; off = 0
            if usize == 0xFFFFFFFF: usize = struct.unpack("<Q", vals[off:off+8])[0]; off += 8
            if csize == 0xFFFFFFFF: csize = struct.unpack("<Q", vals[off:off+8])[0]; off += 8
            if locoff == 0xFFFFFFFF: locoff = struct.unpack("<Q", vals[off:off+8])[0]
        k += 4 + sz2
    entries.append((name, locoff, csize, usize, method))
    i += 46 + nlen + elen + clen2

def extract(name):
    for e in entries:
        if e[0] == name:
            _, locoff, csize, usize, method = e
            s = z.open("assets/main.obb.png"); s.seek(locoff)
            lh = s.read(30); fnl, exl = struct.unpack("<HH", lh[26:30])
            s.seek(locoff + 30 + fnl + exl); data = s.read(csize); s.close()
            return data
    return None

print("=== 提取 .pak ===")
for e in entries:
    if e[0].lower().endswith(".pak"):
        data = extract(e[0])
        fn = os.path.join(OUTP, os.path.basename(e[0]))
        open(fn, "wb").write(data)
        print("  %-55s %d B -> %s" % (e[0], len(data), fn))

# ---- 解析 FPakInfo ----
PAK_MAGIC = 0x5A6F12E1
print("\n=== 解析 FPakInfo ===")
for e in entries:
    if not e[0].lower().endswith(".pak"):
        continue
    fn = os.path.join(OUTP, os.path.basename(e[0]))
    d = open(fn, "rb").read()
    # FPakInfo 在末尾，magic 在前
    pos = d.rfind(struct.pack("<I", PAK_MAGIC))
    if pos < 0:
        print("  %s: 无 FPakInfo" % fn); continue
    ver = struct.unpack_from("<I", d, pos+4)[0]
    idx_off = struct.unpack_from("<Q", d, pos+8)[0]
    idx_size = struct.unpack_from("<Q", d, pos+16)[0]
    idx_hash = d[pos+24:pos+44]
    print("  %s  version=%d idx_off=%d idx_size=%d" % (os.path.basename(fn), ver, idx_off, idx_size))
    # 索引区: FString MountPoint (int32 len incl null, 负数=UTF16)
    io = idx_off
    mlen = struct.unpack_from("<i", d, io)[0]
    if mlen > 0:
        mp = d[io+4:io+4+mlen].decode("utf8", "replace")
        io += 4 + mlen
    else:
        mp = d[io+4:io+4+(-mlen)*2].decode("utf-16-le", "replace")
        io += 4 + (-mlen)*2
    print("    MountPoint=%r" % mp)
    n_entries = struct.unpack_from("<i", d, io)[0]; io += 4
    path_hash_seed = struct.unpack_from("<Q", d, io)[0]; io += 8
    print("    NumEntries=%d pathHashSeed=%#x" % (n_entries, path_hash_seed))
    # 是否有 path-hash index / full directory index (bool)
    if ver >= 7:
        has_ph = d[io]; io += 1
        has_fdi = d[io]; io += 1
        print("    bHasPathHashIndex=%d bHasFullDirectoryIndex=%d" % (has_ph, has_fdi))
    # 尝试 dump 索引区前 256B 看文件名
    seg = d[io:io+400]
    print("    索引区 hex:", seg[:64].hex(" "))
    print("    索引区 ascii:", "".join(chr(c) if 32 <= c < 127 else "." for c in seg[:200]))

# ---- utoc 压缩方法名 + flags ----
print("\n=== utoc 压缩方法 / flags ===")
for fn in ["pakchunk0-Android_ASTC.utoc", "pakchunk1-Android_ASTC.utoc"]:
    d = open(os.path.join(OUTU, fn), "rb").read()
    ver, hdr, entrycnt, blkcnt, blkent, mcnt, mlen, cblk, dirsz, pad = struct.unpack_from("<IIIIIIIIII", d, 16)
    flags = d[80]
    keyguid = d[64:80]
    print("  %s: ver=%d flags=%d keyguid=%s" % (fn, ver, flags, keyguid.hex()))
    # 压缩方法名: 紧跟头之后
    names = d[hdr:hdr+mcnt*mlen]
    print("    方法名区(offset %d):" % hdr, names, "->", names.rstrip(b"\x00").decode("latin1", "replace"))
    # 也扫前 512B 找 ASCII 名
    head = d[:512]
    for m in re.finditer(rb"[A-Za-z][A-Za-z0-9_]{3,}", head):
        s2 = m.group(0)
        if s2.lower() in (b"oodle", b"zlib", b"none", b"lz4", b"oodle1"):
            print("    命中方法名 @%d: %s" % (m.start(), s2))
