# -*- coding: utf-8 -*-
"""手解 UE IoStore .utoc 头，打印字段并定位加密目录索引。"""
import struct

UTOC = r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.utoc"
MAGIC = bytes.fromhex("2D3D3D2D2D3D3D2D2D3D3D2D2D3D3D2D")  # "-==--==--==--==-"

data = open(UTOC, "rb").read()
print(f"文件大小 = 0x{len(data):x} ({len(data)} 字节)")
print(f"Magic 命中: {data[:16] == MAGIC}")
print("\n前 128 字节:")
for i in range(0, 128, 16):
    hx = " ".join(f"{b:02x}" for b in data[i:i+16])
    print(f"  {i:04x}: {hx}")

# 按 UE5 IoStoreTocHeader 解析（小端）
o = 16
version = data[o]; o += 1
print(f"\nVersion = {version} (0=Invalid,1=Initial,2=DirectoryIndex,3=PartitionSize,4=PerfectHash,5=PerfectHashWithOverflow,6=OnDemandMeta,7=RemovedOnDemandMeta,8=ReplaceIoChunkHashWithIoHash)")
o += 1  # Reserved0
o += 2  # Reserved1

def u32(off): return struct.unpack_from("<I", data, off)[0]
def u64(off): return struct.unpack_from("<Q", data, off)[0]

TocHeaderSize = u32(o); o += 4
TocEntryCount = u32(o); o += 4
CompBlockEntryCount = u32(o); o += 4
CompBlockEntrySize = u32(o); o += 4
CompMethodNameCount = u32(o); o += 4
CompMethodNameLength = u32(o); o += 4
CompressionBlockSize = u32(o); o += 4
DirectoryIndexSize = u32(o); o += 4
o += 4  # Pad
PartitionCount = u64(o); o += 8
PartitionSize = u64(o); o += 8
EncryptionKeyGuid = data[o:o+16]; o += 16
ContainerFlags = data[o]; o += 1

print(f"\nTocHeaderSize          = 0x{TocHeaderSize:x}")
print(f"TocEntryCount          = {TocEntryCount}")
print(f"CompBlockEntryCount    = {CompBlockEntryCount}")
print(f"CompBlockEntrySize     = {CompBlockEntrySize}")
print(f"CompMethodNameCount    = {CompMethodNameCount}")
print(f"CompMethodNameLength   = {CompMethodNameLength}")
print(f"CompressionBlockSize   = 0x{CompressionBlockSize:x} ({CompressionBlockSize})")
print(f"DirectoryIndexSize     = 0x{DirectoryIndexSize:x} ({DirectoryIndexSize})")
print(f"PartitionCount         = {PartitionCount}")
print(f"PartitionSize          = 0x{PartitionSize:x}")
print(f"EncryptionKeyGuid      = {EncryptionKeyGuid.hex()}")
print(f"ContainerFlags         = 0x{ContainerFlags:02x}")

o += 1
o += 3  # pad
# 之后还可能有：TocChunkPerfectHashSeedsCount, PartitionSize?, TocChunksWithoutPerfectHashCount...
# 保守：打印接下来的 64 字节，人工核对
print(f"\n[0x{o:x}..] 后续 64 字节（用于定位后续字段与目录索引起点）:")
for i in range(o, o+64, 16):
    print(f"  {i:04x}: " + " ".join(f"{b:02x}" for b in data[i:i+16]))

# 目录索引起点估算：TocHeaderSize + entries + comp blocks + method names
est = TocHeaderSize + TocEntryCount*TocCompBlockEntrySize_placeholder if False else None
toc_entries = TocEntryCount * 12   # FIoStoreTocEntry: 20 bytes(2x u64 hashes + u32) ? 视版本
print("\n提示：目录索引 = TOC 头 + 各条目区之后；它 = Oodle压缩 + AES-256加密。")
print("加密索引大小 DirectoryIndexSize =", DirectoryIndexSize)
