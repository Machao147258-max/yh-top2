"""列出 libmxcore.so 的依赖和导入符号"""
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

so = r"D:\qiling\work\libmxcore.so"
f = open(so, "rb")
elf = ELFFile(f)

print("=== DT_NEEDED ===")
for seg in elf.iter_segments():
    if seg.header.p_type == 'PT_DYNAMIC':
        for tag in seg.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                print("  ", tag.needed)

print("\n=== 导入符号 (undefined dynsym) ===")
dynsym = elf.get_section_by_name('.dynsym')
imps = []
for sym in dynsym.iter_symbols():
    if sym['st_shndx'] == 'SHN_UNDEF' and sym.name:
        imps.append(sym.name)
print(f"  共 {len(imps)} 个:")
for n in imps:
    print("   ", n)

print("\n=== PLT 重定位 (前 40) ===")
for sec in elf.iter_sections():
    if isinstance(sec, RelocationSection) and sec.name in ('.rela.plt', '.rel.plt'):
        print(f"  section {sec.name}: {sec.num_relocations()} 个")
        for i, rel in enumerate(sec.iter_relocations()):
            if i >= 40: break
            sym = dynsym.get_symbol(rel['r_info_sym'])
            print(f"    got={rel['r_offset']:#x}  ->  {sym.name}")
f.close()
