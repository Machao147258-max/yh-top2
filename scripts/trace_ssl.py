"""静态定位 libmxcore.so 的 SSL_write/SSL_read 调用点"""
import capstone
from pathlib import Path

so_path = Path(r"C:\Users\20751\Desktop\异环\unpacked\so\libmxcore.so")
data = open(so_path, "rb").read()

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# 1. 找 "SSL_write" 和 "SSL_read" 字符串位置
str_ssl_write = b"SSL_write"
str_ssl_read  = b"SSL_read"

pos_write = data.find(str_ssl_write)
pos_read  = data.find(str_ssl_read)

print(f"SSL_write 字符串 @ 文件偏移: {hex(pos_write)}")
print(f"SSL_read  字符串 @ 文件偏移: {hex(pos_read)}")

# 2. 在字符串附近搜 ADRP 指令（加载字符串地址的典型方式）
# ARM64 加载全局地址: adrp xN, page ; add xN, xN, #offset
# 在字符串地址附近 4MB 范围内搜

def find_adrp_to_addr(data, target_addr):
    """在文件中搜 adrp 指令，看目标地址是否在 page 范围内"""
    results = []
    md_only_adrp = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    
    # 在 target_addr 前后 0x2000 字节范围内搜 adrp
    search_start = max(0, target_addr - 0x2000)
    search_end = min(len(data), target_addr + 0x2000)
    
    for i in range(search_start, search_end - 4):
        try:
            for insn in md_only_adrp.disasm(data[i:i+8], i):
                if insn.mnemonic == "adrp":
                    # ARM64 ADRP: 计算目标 page
                    # 简单判断：adrp 的目标 page 是否包含 target_addr
                    results.append(i)
        except:
            pass
    
    return results[:10]

# 3. 直接搜 "SSL_write" 和 "SSL_read" 周围的反汇编
print("\n=== SSL_write 周围指令 ===")
offset = pos_write
pre = max(0, offset - 64)
post = min(len(data), offset + 64)
for insn in md.disasm(data[pre:post], pre):
    marker = " ← SSL_write" if insn.address == pos_write else ""
    if abs(insn.address - offset) < 64:
        print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}{marker}")

print("\n=== SSL_read 周围指令 ===")
offset = pos_read
pre = max(0, offset - 64)
post = min(len(data), offset + 64)
for insn in md.disasm(data[pre:post], pre):
    marker = " ← SSL_read" if insn.address == pos_read else ""
    if abs(insn.address - offset) < 64:
        print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}{marker}")

# 4. 在字符串附近框一个函数范围（找序言）
def find_function_start(data, addr, max_back=0x200):
    """从 addr 往回找 stp x29, x30 序言"""
    start = max(0, addr - max_back)
    chunk = data[start:addr]
    # ARM64 序言特征: stp x29, x30, [sp, #-imm]!
    for i in range(len(chunk) - 4, -1, -2):
        for insn in md.disasm(chunk[i:i+8], start + i):
            if insn.mnemonic == "stp" and "x29" in insn.op_str and "x30" in insn.op_str:
                return insn.address
            break
    return None

# 5. 字符串引用点附近找调用函数
for name, addr in [("SSL_write", pos_write), ("SSL_read", pos_read)]:
    # 字符串在 .rodata 段，调用者通过 adrp+add 加载地址
    # 搜字符串地址附近的 ADRP
    print(f"\n=== {name} 调用点搜索 ===")
    
    # 在字符串前后 0x100 内搜 ADRP（加载这个字符串）
    search_from = max(0, addr - 0x4000)
    search_to = min(len(data), addr + 0x100)
    
    found_callers = set()
    for i in range(search_from, search_to - 4):
        for insn in md.disasm(data[i:i+8], i):
            if insn.mnemonic == "adrp":
                # 估算目标 page
                try:
                    op = insn.op_str
                    if "#0x" in op or "#0X" in op:
                        page_str = op.split("#")[1].split(",")[0].strip()
                        target_page = int(page_str, 16)
                        # 如果 page 接近我们字符串的 page
                        if abs(target_page - (addr & ~0xFFF)) < 0x1000:
                            found_callers.add(i)
                except:
                    pass
            break
    
    if found_callers:
        print(f"  找到 {len(found_callers)} 个可能的 ADRP 引用")
        for caller in list(found_callers)[:5]:
            func_start = find_function_start(data, caller)
            if func_start:
                print(f"  ADRP @ {hex(caller)} → 所属函数 @ {hex(func_start)}")
            else:
                print(f"  ADRP @ {hex(caller)}（无标准序言）")
    else:
        print(f"  未找到 ADRP 引用（可能通过其他方式引用）")

print("\n=== 总结 ===")
print(f"SSL_write 字符串: .rodata @ {hex(pos_write)}")
print(f"SSL_read  字符串: .rodata @ {hex(pos_read)}")
print("OpenSSL 函数地址需 IDA GUI 或更多上下文确定")