"""查 GOT 0xb0d900 对应符号 + 0x9e2c0 是啥 + Qiling 加载后 GOT 值"""
import sys
sys.path.insert(0, r"D:\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

so = r"D:\qiling\work\libmxcore.so"
f = open(so, "rb")
elf = ELFFile(f)
dynsym = elf.get_section_by_name('.dynsym')

# 1. 找 got=0xb0d900 的重定位
print("=== 0xb0d900 附近的重定位 ===")
for sec in elf.iter_sections():
    if isinstance(sec, RelocationSection):
        for rel in sec.iter_relocations():
            if 0xb0d8f0 <= rel['r_offset'] <= 0xb0d910:
                sym = dynsym.get_symbol(rel['r_info_sym'])
                print(f"   [{sec.name}] got={rel['r_offset']:#x} type={rel['r_info_type']} -> {sym.name} shndx={sym['st_shndx']} value={sym['st_value']:#x}")

# 2. 文件 0x9e2c0 处
print("\n=== 文件 0x9e2c0 处反汇编 ===")
f.seek(0x9e2c0)
code = f.read(24)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for insn in md.disasm(code, 0x9e2c0):
    print(f"   {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

# 3. 0x9e2c0 是否在某个符号
print("\n=== 0x9e2c0 附近符号 ===")
best = None
for sym in dynsym.iter_symbols():
    v = sym['st_value']
    if v and v <= 0x9e2c0 and (best is None or v > best[1]):
        best = (sym.name, v, sym['st_shndx'])
print(f"   最近符号: {best}")

# 4. Qiling 加载后读 GOT
from qiling import Qiling
from qiling.const import QL_VERBOSE
ql = Qiling([so], rootfs=r"D:\qiling\rootfs\rootfs-master\arm64_android", verbose=QL_VERBOSE.DISABLED)
base = ql.loader.load_address
try:
    got = ql.unpack64(ql.mem.read(base + 0xb0d900, 8))
    print(f"\n=== Qiling: GOT[0xb0d900] = {got:#x}  (base={base:#x}) ===")
    # 该地址内容
    tgt = ql.mem.read(got, 16) if got else b""
    print(f"   目标处字节: {tgt.hex()}")
except Exception as e:
    print(f"[!] {e}")
f.close()
