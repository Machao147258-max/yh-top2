# -*- coding: utf-8 -*-
"""libsecsdk 链接全景 + 探测字符串 + .so 互相依赖。"""
import os, re, glob
from elftools.elf.elffile import ELFFile
from collections import defaultdict
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
dynstr=elf.get_section_by_name('.dynstr'); dyn=elf.get_section_by_name('.dynamic')
def tags(t): return [dynstr.get_string(e.entry.d_val) for e in dyn.iter_tags() if e.entry.d_tag==t]
print("NEEDED:", tags('DT_NEEDED'))
print("SONAME:", tags('DT_SONAME'))
print("RPATH :", tags('DT_RPATH'))
print("RUNPATH:", tags('DT_RUNPATH'))
# 分类导入
LIBMAP={
 'libz.so':{'uncompress','compress','inflate','deflate','crc32','adler32','inflateInit_','deflateInit_'},
 'libm.so':{'fmod','fmodf','pow','sqrt','sin','cos','log','exp','atan2','floor','ceil'},
 'libdl.so':{'dlopen','dlsym','dlclose','dlerror','dl_iterate_phdr','dladdr'},
 'liblog.so':set(),  # 待填
}
def detect_lib(name):
    if name.startswith(('__cxa_','_Z','_Znw','_Zdl')): return 'libstdc++'
    if name in ('uncompress','compress','crc32','adler32','inflate','deflate','infback','inflateInit2_','deflateInit2_'): return 'libz'
    if name in ('fmod','fmodf','pow','sqrt','sin','cos','log','exp','atan2','floor','ceil','round','nan','isnan'): return 'libm'
    if name in ('dlopen','dlsym','dlclose','dlerror','dl_iterate_phdr','dladdr'): return 'libdl'
    if name.startswith('__android_log'): return 'liblog'
    return 'libc'
dynsym=elf.get_section_by_name('.dynsym')
g=defaultdict(list)
for s in dynsym.iter_symbols():
    if s['st_shndx']=='SHN_UNDEF' and s.name: g[detect_lib(s.name)].append(s.name)
print("\n=== 导入按库分组 ===")
for lib,syms in sorted(g.items()):
    print(f"[{lib}] ({len(syms)}): {', '.join(sorted(syms))}")
print("\n=== 导出符号 ===")
exps=[s.name for s in dynsym.iter_symbols() if s['st_shndx']!='SHN_UNDEF' and s.name and s['st_info']['type'] in ('STT_FUNC','STT_GNU_IFUNC')]
print(f"  {len(exps)} 个: {exps[:40]}")

# ==== 探测字符串 ====
print("\n=== 可疑字符串(探测点) ===")
pats=[rb"/proc/[a-z_/]+", rb"/system/[a-zA-Z0-9_/.]+", rb"/data/[a-zA-Z0-9_/.]+",
      rb"ro\.[a-z_.]+", rb"persist\.[a-z_.]+", rb"magisk", rb"/su\b", rb"frida", rb"xposed",
      rb"hottagames[a-z.]*", rb"yh\.laohu", rb"secsdk", rb"libc\.so", rb"libsecsdk"]
sents=set()
for p in pats:
    for m in re.finditer(p, raw):
        try: sents.add(m.group().decode('latin1'))
        except: pass
for s in sorted(sents)[:80]: print("  ",s)
f.close()

# ==== 所有 .so 的互相依赖 ====
print("\n=== 应用内 .so 依赖图 ===")
so_dir=r"C:\Users\20751\Desktop\异环\unpacked\so"
for p in sorted(glob.glob(os.path.join(so_dir,"*.so"))):
    try:
        ff=open(p,"rb"); e=ELFFile(ff); ds=e.get_section_by_name('.dynstr')
        if not ds: ff.close(); continue
        nd=[ds.get_string(t.entry.d_val) for t in e.get_section_by_name('.dynamic').iter_tags() if t.entry.d_tag=='DT_NEEDED'] if e.get_section_by_name('.dynamic') else []
        game=[x for x in nd if x.startswith('lib') and x in ("libUnreal.so","libthemis.so","libsecsdk.so","libmxcore.so","libclient.so","libmain.so","libanogs.so")]
        print(f"  {os.path.basename(p)}: NEEDED={nd}")
        ff.close()
    except Exception as ex: print(f"  {os.path.basename(p)}: {ex}")
