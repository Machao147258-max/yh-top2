"""ARM64: 搜 ADRP 指令定位 SSL_write/SSL_read 调用者"""
import struct
from pathlib import Path

so_path = Path(r"C:\Users\20751\Desktop\异环\unpacked\so\libmxcore.so")
data = open(so_path, "rb").read()

# 已知字符串位置 (yakit_grep 结果)
TARGETS = {
    "SSL_read":  0x96dce0,
    "SSL_write": 0x96e148,
}

def find_text_section(data):
    """找 .text 段的偏移和范围"""
    if data[:4] != b'\x7fELF':
        return None, None, None
    
    e_phoff = struct.unpack('<Q', data[0x20:0x28])[0]
    e_phnum = struct.unpack('<H', data[0x38:0x3A])[0]
    
    for i in range(e_phnum):
        off = e_phoff + i * 0x38
        p_type = struct.unpack('<I', data[off:off+4])[0]
        if p_type == 1:  # PT_LOAD
            p_flags = struct.unpack('<I', data[off+4:off+8])[0]
            p_offset = struct.unpack('<Q', data[off+8:off+0x10])[0]
            p_vaddr = struct.unpack('<Q', data[off+0x10:off+0x18])[0]
            p_filesz = struct.unpack('<Q', data[off+0x20:off+0x28])[0]
            
            if p_flags & 1:  # PF_X (可执行)
                return p_offset, p_vaddr, p_filesz
    
    return None, None, None

text_off, text_vaddr, text_size = find_text_section(data)
if text_off is None:
    print("[×] 找不到 text 段")
    exit()

print(f".text 段: 文件偏移 {hex(text_off)}, vaddr {hex(text_vaddr)}, 大小 {hex(text_size)}B")

for name, str_addr in TARGETS.items():
    # 目标字符串所在 page (4K)
    target_page = str_addr & ~0xFFF  
    
    # 在 .text 里搜 ADRP
    callers = []
    text_data = data[text_off:text_off+text_size]
    
    i = 0
    while i < len(text_data) - 4:
        # ARM64 ADRP 编码: 1xx10000... (0x90 = 10010000)
        insn = struct.unpack('<I', text_data[i:i+4])[0]
        if (insn >> 24) & 0xFE == 0x90:  # ADRP
            # 解码 ADRP 目标
            # ADRP xd, label: immhi:immlo
            immhi = (insn >> 5) & 0x7FFFF
            immlo = (insn >> 29) & 3
            imm = (immhi << 2) | immlo
            page = (text_vaddr + i) & ~0xFFF
            target = page + (imm << 12)
            
            if target == target_page:
                caller_addr = text_vaddr + i
                # 看下一条指令是不是 ADD (加载偏移)
                next_insn = struct.unpack('<I', text_data[i+4:i+8])[0]
                if (next_insn >> 24) == 0x91:  # ADD (immediate)
                    off = (next_insn >> 10) & 0xFFF
                    actual_target = target + off
                    if actual_target == str_addr:
                        callers.append(caller_addr)
                elif (next_insn >> 24) == 0x91:  # 也可能是其他 ADD 形式
                    callers.append(caller_addr)
                else:
                    callers.append(caller_addr)
                    break
        i += 4
    
    print(f"\n=== '{name}' @ {hex(str_addr)} (page {hex(target_page)}) ===")
    if callers:
        print(f"找到 {len(callers)} 个 ADRP 引用:")
        for c in callers[:15]:
            # 向前找函数序言
            func_start = None
            for back in range(min(0x400, c - text_vaddr)):
                check = c - back
                if check - text_vaddr < 4:
                    break
                insn_b = struct.unpack('<I', text_data[check-text_vaddr:check-text_vaddr+4])[0]
                # stp x29, x30, [sp, #-imm]! → 0xA9BF7BFD (典型)
                if (insn_b & 0xFFC00000) == 0xA9800000 and ((insn_b >> 16) & 0x1F) == 29:
                    func_start = check
                    break
            if func_start:
                print(f"  ADRP @ {hex(c)} → 函数 @ {hex(func_start)}")
            else:
                print(f"  ADRP @ {hex(c)}（无标准序言）")
        
        if len(callers) > 15:
            print(f"  ... 还有 {len(callers)-15} 个")
    else:
        print("  未找到 ADRP 引用")
        print(f"  (检查 page 偏移: 目标 {hex(target_page)}, 代码段范围 {hex(text_vaddr)}-{hex(text_vaddr+text_size)})")

# 额外: 搜整段代码看有几个 SSL_write 引用
print("\n\n=== 总搜索: 代码段中 SSL_write/SSL_read 字节 ===")
ssl_write_bytes = b"SSL_write"
ssl_read_bytes = b"SSL_read"
for name, bs in [("SSL_write", ssl_write_bytes), ("SSL_read", ssl_read_bytes)]:
    count = text_data.count(bs)
    print(f"  '{name}' 在 .text 中出现: {count} 次")

# 字符串段中的位置
total_count_write = data.count(ssl_write_bytes)
total_count_read = data.count(ssl_read_bytes)
print(f"  'SSL_write' 在文件中总出现: {total_count_write} 次")
print(f"  'SSL_read' 在文件中总出现: {total_count_read} 次")