"""检查 libmxcore.so 的文件偏移→虚址映射"""
import struct
from pathlib import Path

path = Path(r"C:\Users\20751\Desktop\异环\unpacked\so\libmxcore.so")
data = open(path, "rb").read()

if data[:4] != b'\x7fELF':
    print("不是 ELF")
    exit()

# ELF Header
e_phoff = struct.unpack('<Q', data[0x20:0x28])[0]
e_phnum = struct.unpack('<H', data[0x38:0x3A])[0]

print("程序头(LOAD段):")
print(f"{'类型':>6} | {'文件偏移':>12} | {'虚址':>12} | {'大小':>10} | {'权限':>4}")
print("-" * 55)

for i in range(e_phnum):
    off = e_phoff + i * 0x38
    p_type = struct.unpack('<I', data[off:off+4])[0]
    if p_type == 1:  # PT_LOAD
        p_flags = struct.unpack('<I', data[off+4:off+8])[0]
        p_offset = struct.unpack('<Q', data[off+8:off+0x10])[0]
        p_vaddr = struct.unpack('<Q', data[off+0x10:off+0x18])[0]
        p_filesz = struct.unpack('<Q', data[off+0x20:off+0x28])[0]
        
        perm = ""
        if p_flags & 4: perm += "R"
        if p_flags & 2: perm += "W"
        if p_flags & 1: perm += "X"
        
        offset_flag = ""
        if p_offset == p_vaddr:
            offset_flag = " ← 无偏移"
        else:
            offset_flag = f" 偏移={hex(p_vaddr - p_offset)}"
        
        print(f" LOAD | {hex(p_offset):>10} | {hex(p_vaddr):>10} | {hex(p_filesz):>8} | {perm:>3}{offset_flag}")

# SSL_write 字符串位置
ssl_write_file = 0x96e148
ssl_read_file = 0x96dce0

# 算虚址：找到对应 LOAD 段
for i in range(e_phnum):
    off = e_phoff + i * 0x38
    p_type = struct.unpack('<I', data[off:off+4])[0]
    if p_type == 1:
        p_offset = struct.unpack('<Q', data[off+8:off+0x10])[0]
        p_vaddr = struct.unpack('<Q', data[off+0x10:off+0x18])[0]
        p_filesz = struct.unpack('<Q', data[off+0x20:off+0x28])[0]
        
        if p_offset <= ssl_write_file < p_offset + p_filesz:
            delta = ssl_write_file - p_offset
            vaddr_write = p_vaddr + delta
            print(f"\nSSL_write 字符串: 文件偏移 {hex(ssl_write_file)} → 虚址 {hex(vaddr_write)}")
        
        if p_offset <= ssl_read_file < p_offset + p_filesz:
            delta = ssl_read_file - p_offset
            vaddr_read = p_vaddr + delta
            print(f"SSL_read  字符串: 文件偏移 {hex(ssl_read_file)} → 虚址 {hex(vaddr_read)}")

# .text 段
for i in range(e_phnum):
    off = e_phoff + i * 0x38
    p_type = struct.unpack('<I', data[off:off+4])[0]
    if p_type == 1:
        p_flags = struct.unpack('<I', data[off+4:off+8])[0]
        p_offset = struct.unpack('<Q', data[off+8:off+0x10])[0]
        p_vaddr = struct.unpack('<Q', data[off+0x10:off+0x18])[0]
        p_filesz = struct.unpack('<Q', data[off+0x20:off+0x28])[0]
        
        if p_flags & 1:  # 可执行
            print(f"\n.text 段: 文件偏移 {hex(p_offset)} → 虚址 {hex(p_vaddr)}, {p_filesz}B")