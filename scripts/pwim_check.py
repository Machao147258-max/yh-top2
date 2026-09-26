"""检查 pwim 符号性质 + 解码崩掉的 PLT (0x9f7e0)"""
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

so = r"D:\qiling\work\libmxcore.so"
f = open(so, "rb")
elf = ELFFile(f)

dynsym = elf.get_section_by_name('.dynsym')
# 统计 pwim_ 符号的定义情况
from collections import Counter
cnt = Counter()
pwim_samples = []
for sym in dynsym.iter_symbols():
    if sym.name.startswith('pwim'):
        cnt[str(sym['st_shndx'])] += 1
        if len(pwim_samples) < 6:
            pwim_samples.append((sym.name, sym['st_shndx'], hex(sym['st_value']), sym['st_info']['type']))
print("=== pwim_* 符号 st_shndx 分布 ===")
for k, v in cnt.items():
    print(f"   {k}: {v}")
print("   样例:")
for n, sh, val, ty in pwim_samples:
    print(f"     {n}  shndx={sh} value={val} type={ty}")

# 非 pwim 的 undef 定义情况
cnt2 = Counter()
for sym in dynsym.iter_symbols():
    if sym['st_shndx'] == 'SHN_UNDEF' and sym.name:
        cnt2['undef'] += 1
print(f"\n=== SHN_UNDEF 总数: {cnt2['undef']} ===")

# 解码 0x9f7e0 处
print("\n=== 0x9f7e0 处反汇编 ===")
f.seek(0x9f7e0)
code = f.read(32)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for insn in md.disasm(code, 0x9f7e0):
    print(f"   {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

# 找 .rela.plt 里 got=0xa67xxx 附近对应哪个符号（PLT 可能引用 GOT 高位）
# 直接列出几个 GOT 相关
print("\n=== 全部 pwim_* PLT 条目 ===")
from elftools.elf.relocation import RelocationSection
for sec in elf.iter_sections():
    if isinstance(sec, RelocationSection) and sec.name in ('.rela.plt',):
        for rel in sec.iter_relocations():
            sym = dynsym.get_symbol(rel['r_info_sym'])
            if sym.name.startswith('pwim'):
                print(f"   got={rel['r_offset']:#x}  {sym.name}")
f.close()
