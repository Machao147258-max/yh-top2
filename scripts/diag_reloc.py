"""诊断: Qiling 是否应用了 R_AARCH64_RELATIVE 重定位"""
import sys
sys.path.insert(0, r"D:\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling_harness import Harness, SO, ROOTFS

h = Harness(SO, ROOTFS)
ql = h.ql
base = h.base

elf = ELFFile(open(SO, "rb"))
# 找 .rela.dyn 里的 RELATIVE 项
dyn = elf.get_section_by_name('.rela.dyn')
cnt = {}
samples = []
if dyn:
    for rel in dyn.iter_relocations():
        t = rel['r_info_type']
        cnt[t] = cnt.get(t, 0) + 1
        if t == 1027 and len(samples) < 5:   # R_AARCH64_RELATIVE
            samples.append((rel['r_offset'], rel['r_addend']))
print("=== .rela.dyn 类型统计 (1027=RELATIVE) ===")
for t, c in sorted(cnt.items()):
    print(f"  type {t}: {c}")
print("RELATIVE 样例 (offset, addend):")
for off, add in samples:
    print(f"  {off:#x} -> {add:#x}")

print("\n=== 加载后这些位置的实际值 ===")
for off, add in samples:
    try:
        val = ql.unpack64(ql.mem.read(base + off, 8))
        expect = base + add
        ok = "✅" if val == expect else "❌"
        print(f"  [{off:#x}] 实际={val:#x}  期望={expect:#x}  {ok}")
    except Exception as e:
        print(f"  [{off:#x}] 读失败 {e}")
