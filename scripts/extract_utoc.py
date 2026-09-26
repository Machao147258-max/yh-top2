"""从 APK 的 assets/main.obb.png 流式提取 .utoc 资产。
OBB 内部是 ZIP64，EOCD cd_off 超界但 CD 记录(PK0102)就在文件末尾区域。
策略：读最后 ~256KB，在其中直接解析中央目录记录，跳过 EOCD 偏移校验。"""
import zipfile, struct, os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

APK = r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
OUT = r"C:\Users\20751\Desktop\异环\unpacked\utoc"
os.makedirs(OUT, exist_ok=True)

z = zipfile.ZipFile(APK)
obb_size = z.getinfo("assets/main.obb.png").file_size
print("OBB size", obb_size)

TAIL = 512 * 1024
s = z.open("assets/main.obb.png")
s.seek(max(0, obb_size - TAIL))
tail = s.read()
s.close()
print("读取尾部", len(tail), "B")

# EOCD 在最后
eocd = tail.rfind(b"PK\x05\x06")
cd_end = eocd if eocd >= 0 else len(tail)
print("EOCD @", eocd, "CD 区域截至", cd_end)

# 从 EOCD 之前的区域向后扫描 PK0102 记录，收集所有 CD 条目
entries = []
i = 0
while i < cd_end - 46:
    if struct.unpack("<I", tail[i:i+4])[0] != 0x02014b50:
        i += 1
        continue
    v = struct.unpack("<HHHHHHIIIHHHHHII", tail[i+4:i+46])
    (vmade, vneed, flags, method, mt, md, crc, csize, usize, nlen, elen, clen2, disk, intattr, extattr, locoff) = v
    # 处理 ZIP64 局部字段: 若 usize/csize/locoff == 0xFFFFFFFF, 读 extra 里的 zip64 值
    name = tail[i+46:i+46+nlen].decode("utf8", "replace")
    # 解析 extra (zip64)
    x = i + 46 + nlen
    ex = tail[x:x+elen]
    z64 = {}
    k = 0
    while k + 4 <= len(ex):
        hdr, sz2 = struct.unpack("<HH", ex[k:k+4])
        if hdr == 0x0001:
            vals = ex[k+4:k+4+sz2]
            off = 0
            if usize == 0xFFFFFFFF:
                usize = struct.unpack("<Q", vals[off:off+8])[0]; off += 8
            if csize == 0xFFFFFFFF:
                csize = struct.unpack("<Q", vals[off:off+8])[0]; off += 8
            if locoff == 0xFFFFFFFF:
                locoff = struct.unpack("<Q", vals[off:off+8])[0]
        k += 4 + sz2
    entries.append((name, locoff, csize, usize, method))
    i += 46 + nlen + elen + clen2

print("解析到 OBB 条目:", len(entries))
for n, lo, cs, us, m in entries:
    print("  m%-2d %11d  %-70s" % (m, us, n))

# 提取 utoc（也提取 small global.utoc）
def extract(entry):
    name, locoff, csize, usize, method = entry
    s = z.open("assets/main.obb.png")
    s.seek(locoff)
    lh = s.read(30)
    fnl, exl = struct.unpack("<HH", lh[26:30])
    data_off = locoff + 30 + fnl + exl
    s.seek(data_off)
    data = s.read(csize)
    s.close()
    return data

print("\n=== 提取 .utoc ===")
for e in entries:
    if e[0].lower().endswith(".utoc"):
        try:
            data = extract(e)
            fn = os.path.join(OUT, os.path.basename(e[0]))
            open(fn, "wb").write(data)
            print("  %-60s %d B -> %s" % (e[0], len(data), fn))
        except Exception as ex:
            print("  提取失败", e[0], ex)