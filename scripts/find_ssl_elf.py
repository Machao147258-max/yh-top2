"""从 ELF 动态符号表找 OpenSSL 函数 — 不依赖外部命令"""
import struct
from pathlib import Path

so_path = Path(r"C:\Users\20751\Desktop\异环\unpacked\so\libmxcore.so")
data = open(so_path, "rb").read()

# 手动解析 ELF 头找 .dynsym
if data[:4] != b'\x7fELF':
    print("[×] 不是 ELF 文件")
    exit()

# ELF 64-bit header
e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]  # Section header offset
e_shentsize = struct.unpack('<H', data[0x3A:0x3C])[0]
e_shnum = struct.unpack('<H', data[0x3C:0x3E])[0]
e_shstrndx = struct.unpack('<H', data[0x3E:0x40])[0]

# 读节表找 .dynsym .dynstr
sections = {}
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name = struct.unpack('<I', data[off:off+4])[0]
    sh_type = struct.unpack('<I', data[off+4:off+8])[0]
    sh_flags = struct.unpack('<Q', data[off+8:off+0x10])[0]
    sh_addr = struct.unpack('<Q', data[off+0x10:off+0x18])[0]
    sh_offset = struct.unpack('<Q', data[off+0x18:off+0x20])[0]
    sh_size = struct.unpack('<Q', data[off+0x20:off+0x28])[0]
    sh_link = struct.unpack('<I', data[off+0x28:off+0x2C])[0]
    sh_entsize = struct.unpack('<Q', data[off+0x38:off+0x40])[0]
    
    # 节名字符串表
    strtab_off = e_shoff + e_shstrndx * e_shentsize
    strtab_sh_offset = struct.unpack('<Q', data[strtab_off+0x18:strtab_off+0x20])[0]
    
    # 读节名
    name_end = data.find(b'\x00', strtab_sh_offset + sh_name)
    sec_name = data[strtab_sh_offset + sh_name:name_end].decode('ascii', errors='replace')
    
    sections[sec_name] = {
        'addr': sh_addr,
        'offset': sh_offset,
        'size': sh_size,
        'entsize': sh_entsize,
        'link': sh_link,
    }

# 找到 .dynsym 和 .dynstr
if '.dynsym' not in sections or '.dynstr' not in sections:
    print("[×] no .dynsym / .dynstr")
    # 显示有哪些节
    print("可用节:", list(sections.keys())[:30])
    exit()

dynsym = sections['.dynsym']
dynstr = sections['.dynstr']

# 解析动态符号
symbol_size = dynsym['entsize']  # 通常是 0x18 (64-bit ELF)
n_syms = dynsym['size'] // symbol_size

print(f"\n.dynsym: {n_syms} 个符号")
print(f".dynstr: {dynstr['size']} 字节")

# 分类符号
imported = []   # STB_GLOBAL + SHN_UNDEF = 导入
exported = []   # 定义在本 SO 的

for i in range(min(n_syms, 50000)):
    sym_off = dynsym['offset'] + i * symbol_size
    
    if symbol_size == 0x18:
        st_name = struct.unpack('<I', data[sym_off:sym_off+4])[0]
        st_info = struct.unpack('B', data[sym_off+4:sym_off+5])[0]
        st_shndx = struct.unpack('<H', data[sym_off+6:sym_off+8])[0]
    else:
        continue
    
    sym_type = st_info & 0xF
    sym_bind = st_info >> 4
    
    # 读符号名
    name_end = data.find(b'\x00', dynstr['offset'] + st_name)
    sym_name = data[dynstr['offset'] + st_name:name_end].decode('ascii', errors='replace')
    
    if not sym_name:
        continue
    
    # 导入 = SHN_UNDEF (0) 且是全局的
    if st_shndx == 0 and sym_bind == 1:  # STB_GLOBAL + UNDEF
        if any(kw in sym_name for kw in ['SSL', 'ssl', 'BIO', 'OPENSSL', 'CRYPTO', 'X509', 
                                           'PEM', 'EVP', 'RSA', 'EC', 'DH', 'DSA']):
            imported.append(sym_name)
    # 导出
    elif st_shndx != 0 and sym_bind == 1:
        if any(kw in sym_name for kw in ['SSL', 'ssl', 'BIO', 'OPENSSL', 'CRYPTO', 'X509']):
            exported.append(sym_name)

print(f"\n=== 导入的 OpenSSL 符号 ({len(imported)}) ===")
if imported:
    for s in sorted(set(imported))[:40]:
        print(f"  {s}")
else:
    print("  (无) — OpenSSL 是静态链接的，函数体在 .text 里")

print(f"\n=== 导出的 OpenSSL 符号 ({len(exported)}) ===")
if exported:
    for s in sorted(set(exported))[:20]:
        print(f"  {s}")
else:
    print("  (无)")
    print("\n结论: OpenSSL 是静态链接到 libmxcore.so 的")
    print("函数体在 .text 中，但没有导出符号")

# 静态链接 OpenSSL 时，函数仍然有符号名，但不在 .dynsym 而在 .symtab
# 如果 .symtab 被 strip 掉了，就真找不到了
if '.symtab' in sections:
    print(f"\n.symtab 存在 ({sections['.symtab']['size']}B) — 可以找到函数名")
else:
    print(f"\n.symtab 被 strip — 函数名不可见")
    print("想精确定位 SSL_write 需要 IDA GUI 的 xref")