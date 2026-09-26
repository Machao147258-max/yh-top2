# -*- coding: utf-8 -*-
"""libsecsdk 链接全景: DT_NEEDED + 每个导入来自哪个so(按版本) + 找zlib压缩载荷。"""
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerNeedSection
import zlib, re
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
dynstr=elf.get_section_by_name('.dynstr'); dyn=elf.get_section_by_name('.dynamic')
needed=[dynstr.get_string(t.entry.d_val) for t in dyn.iter_tags() if t.entry.d_tag=='DT_NEEDED']
print("=== DT_NEEDED (直接依赖) ===")
for n in needed: print("  ",n)
# 版本 -> 所属库
ver2lib={}
for sec in elf.iter_sections():
    if isinstance(sec, GNUVerNeedSection):
        for verneed, vernauxs in sec.iter_versions():
            for va in vernauxs:
                ver2lib[va.name] = verneed.name
# undef 符号 -> 版本 -> 库
dynsym=elf.get_section_by_name('.dynsym')
def sym_ver(i):
    try:
        vs=elf.get_section_by_name('.gnu.version')
        return vs.get_symbol(i)['ndx']
    except: return None
print("\n=== 导入符号按库分组 ===")
from collections import defaultdict
bylib=defaultdict(list)
for i,s in enumerate(dynsym.iter_symbols()):
    if s['st_shndx']=='SHN_UNDEF' and s.name:
        bylib['?'].append(s.name)
# 用 verneed 尝试归类
verneed_by_lib={}
for sec in elf.iter_sections():
    if isinstance(sec, GNUVerNeedSection):
        for verneed, vernauxs in sec.iter_versions():
            for va in vernauxs:
                verneed_by_lib[va.name]=verneed.name
# 逐个 undef 符号，找它引用的版本
for i,s in enumerate(dynsym.iter_symbols()):
    if s['st_shndx']=='SHN_UNDEF' and s.name:
        # 找引用该符号的 reloc 的版本 (近似: 用 .gnu.version[idx])
        pass
# 简化: 直接列版本需求
print("版本需求(每个库):")
for sec in elf.iter_sections():
    if isinstance(sec, GNUVerNeedSection):
        for verneed, vernauxs in sec.iter_versions():
            vers=[va.name for va in vernauxs]
            print(f"  {verneed.name}: {vers}")

# ==== 找 zlib 压缩流 ====
print("\n=== 扫描 zlib 压缩流 (magic 78 01/9c/da/5e) ===")
found=0
for off in range(0, len(raw)-2):
    if raw[off]==0x78 and raw[off+1] in (0x01,0x9c,0xda,0x5e):
        try:
            d=zlib.decompressobj()
            out=d.decompress(raw[off:off+0x400000])
            if len(out)>=64:
                found+=1
                print(f"  0x{off:x}: 解压 {len(out)} 字节, 头: {out[:48]!r}")
                if found<=8: open(rf"D:\qwork\secsdk_blob_{off:x}.bin","wb").write(out)
        except Exception: pass
    if found>40: break
print(f"共发现 zlib 流 {found} 个")
f.close()
