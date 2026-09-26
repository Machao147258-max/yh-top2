"""只看短 SSL/TLS 字符串 + 符号表里的 SSL_ 名字"""
import re
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()

pat = re.compile(rb"[\x20-\x7e]{4,}")
seen = set()
print("=== 短 SSL/TLS 字符串 (<90 字符) ===")
for m in pat.finditer(data):
    s = m.group()
    if len(s) > 90:
        continue
    low = s.lower()
    if b'ssl' in low or b'tls' in low or b'x509' in low:
        t = s.decode('latin1')
        key = t.strip()
        if key in seen:
            continue
        seen.add(key)
        print(f"  off={m.start():#08x}  {t}")
print(f"\n共 {len(seen)} 条唯一短串")

# 符号表
from elftools.elf.elffile import ELFFile
elf = ELFFile(open(SO, "rb"))
print("\n=== 符号表中的 SSL_/TLS_/X509_ 名字 ===")
for secname in ('.dynsym', '.symtab'):
    sec = elf.get_section_by_name(secname)
    if not sec:
        continue
    for sym in sec.iter_symbols():
        n = sym.name
        if n.startswith(('SSL_', 'TLS_', 'X509_', 'ssl_', 'tls_')) or 'SSL' in n:
            print(f"  [{secname}] {n}  value={sym['st_value']:#x} shndx={sym['st_shndx']}")
