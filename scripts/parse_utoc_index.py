"""解析 UE5 IoStore .utoc 目录索引，提取资产文件路径。
目录索引在 .utoc 末尾 (DirectoryIndexSize)，通常 Oodle 或 zlib 压缩。
先识别压缩类型，再解压目录 (FDirectoryIndexHeader -> string 列表)。"""
import struct, zlib, os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

D = r"C:\Users\20751\Desktop\异环\unpacked\utoc"
OUT = r"C:\Users\20751\Desktop\异环\reports"
os.makedirs(OUT, exist_ok=True)

def parse_utoc(fn):
    d = open(os.path.join(D, fn), "rb").read()
    ver, hdr, entrycnt, blkcnt, blkent, mcnt, mlen, cblk, dirsz, pad = struct.unpack_from("<IIIIIIIIII", d, 16)
    idx_off = len(d) - dirsz
    idx = d[idx_off:idx_off+dirsz]
    print("== %s: entries=%d dirsz=%d idx_off=%d" % (fn, entrycnt, dirsz, idx_off))
    # 目录索引头部 (FDirectoryIndexHeader): Magic(4) Version(1) + 各 offset u32
    print("  索引头部 hex:", idx[:48].hex(" "))
    return d, idx, entrycnt, hdr, dirsz, idx_off

def try_compressions(idx):
    # 常见: zlib (0x78 0x9c/0xda), Oodle (自定义)
    print("  索引前8B:", idx[:8].hex(" "))
    if idx[0] == 0x78:
        try:
            dec = zlib.decompress(idx)
            return "zlib", dec
        except Exception as e:
            print("  zlib 失败:", e)
    # 尝试 0x9c2b 魔数 (UE zlib header variant) 或 skookum
    return None, None

for fn in ["pakchunk0-Android_ASTC.utoc", "pakchunk1-Android_ASTC.utoc"]:
    d, idx, entrycnt, hdr, dirsz, idx_off = parse_utoc(fn)
    method, dec = try_compressions(idx)
    if dec:
        open(os.path.join(OUT, fn.replace(".utoc", ".dirindex.zbin")), "wb").write(dec)
        print("  解压成功", method, "->", len(dec), "B")
        # 目录索引解压后: FDirectoryIndexHeader { Magic "DIx" 3B + Version u8 ; PathHashSeed u64; MountPoint string; EntriesOffset u32; EntriesSize u32; StringDataOffset u32; StringDataSize u32 }
        # 先 dump 前 64B
        print("  解压后头:", dec[:64].hex(" "))
    else:
        print("  未能解压(可能 Oodle 或需专用库)")

# global.utoc 特殊: 无 directory index