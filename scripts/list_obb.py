"""List main.obb.png (a zip/OBB) contents by streaming to find EOCD then central dir.

Does not decompress 1GB; only reads central directory (CD) near end.
"""
import struct, zipfile, io, os

APK = r"D:\dwonload\yh_gw_20260702.apk"

z = zipfile.ZipFile(APK)
info = z.getinfo("assets/main.obb.png")
print("obb entry:", info.file_size, "bytes, stored(no compress)")
# The outer entry is stored (method 0), so bytes are contiguous: we can read
# from file offset directly, but simplest: stream the whole entry once.
# 1GB streamed is fine (~seconds locally), but we only need the tail (CD).
# Strategy: stream and keep last ~32MB in memory to find EOCD.
TAIL = 64*1024*1024
src = z.open("assets/main.obb.png")
chunk = src.read(TAIL)
# if shorter than TAIL it's small; else read until we have the last TAIL bytes
while True:
    b = src.read(8*1024*1024)
    if not b:
        break
    chunk = chunk[-TAIL:] + b
tail = chunk[-64*1024*1024:]
src.close()

eocd = tail.rfind(b"PK\x05\x06")
if eocd < 0:
    print("no EOCD found in last 64MB")
    raise SystemExit(1)
rec = tail[eocd:eocd+22]
(disc, cd_disc, n_entries, n_entries2, cd_size, cd_off, clen) = struct.unpack("<HHHHIIH", rec[4:22])
print("OBB EOCD:", "entries", n_entries, "cd_size", cd_size, "cd_offset", cd_off, "comment", clen)

# cd_off is relative to the obb start; we need those bytes. cd_size up to a few MB.
print("reading central directory ...")
src = z.open("assets/main.obb.png")
src.seek(cd_off)
cd = src.read(cd_size)
src.close()
print("cd read", len(cd))

entries = []
i = 0
while i < len(cd) - 46:
    sig = struct.unpack("<I", cd[i:i+4])[0]
    if sig != 0x02014b50:
        i += 1
        continue
    (vmade, vneed, flags, method, mt, md, crc, csize, usize, nlen, elen, clen2,
     disk, intattr, extattr, locoff) = struct.unpack("<HHHHHHIIIHHHHHII", cd[i+4:i+46])
    name = cd[i+46:i+46+nlen].decode("utf8", "replace")
    entries.append((name, usize, csize, method))
    i += 46 + nlen + elen + clen2

print("total OBB entries:", len(entries))

from collections import Counter
exts = Counter()
dirs = Counter()
for n, u, c, m in entries:
    base = os.path.basename(n)
    if "." in base:
        exts[base.rsplit(".", 1)[1].lower()] += 1
    else:
        exts["(none)"] += 1
    parts = n.split("/")
    if len(parts) > 1:
        dirs["/".join(parts[:2])] += 1
    elif n:
        dirs["/"+parts[0]] += 1

print("\n=== top-level dirs (first 2 segments) ===")
for d, c in dirs.most_common(40):
    print("  %6d  %s" % (c, d))

print("\n=== extensions ===")
for e, c in exts.most_common(30):
    print("  %6d  .%s" % (c, e))

print("\n=== biggest 40 ===")
for n, u, c, m in sorted(entries, key=lambda x: -x[1])[:40]:
    print("  %11d  %9d  m%d  %s" % (u, c, m, n))