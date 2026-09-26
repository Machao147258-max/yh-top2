"""反汇编指定函数 (vaddr -> file offset via PT_LOAD)"""
import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"D:\qiling\work\libmxcore.so"
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

f = open(SO, "rb")
elf = ELFFile(f)

# 建 vaddr->offset 映射
segs = []
for seg in elf.iter_segments():
    if seg.header.p_type == 'PT_LOAD':
        segs.append((seg.header.p_vaddr, seg.header.p_offset, seg.header.p_filesz))

def v2o(v):
    for va, off, sz in segs:
        if va <= v < va + sz:
            return off + (v - va)
    return None

def disasm_func(vaddr, max_bytes=600):
    off = v2o(vaddr)
    if off is None:
        print(f"  [!] {vaddr:#x} 不在任何段")
        return
    f.seek(off)
    code = f.read(max_bytes)
    print(f"\n=== {vaddr:#x} ===")
    n = 0
    for insn in MD.disasm(code, vaddr):
        mark = ""
        if insn.mnemonic in ("bl",) and insn.op_str.startswith("#"):
            tgt = int(insn.op_str[1:], 16)
            mark = f"   ; -> {tgt:#x}"
        print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}{mark}")
        n += 1
        if insn.mnemonic == "ret" and n > 2:
            break
        if n > 150:
            print("  ... (截断)")
            break

for v in [0x489DBC, 0x48BA1C, 0x489C68, 0x500C20, 0x5011E4]:
    disasm_func(v)

f.close()
