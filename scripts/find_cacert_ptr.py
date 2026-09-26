"""找 ct_cacert.pem 的指针引用 + 看 0x551c68 函数"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# 1. 原始指针搜索
for name, val in [("ct_cacert.pem", 0x95126d), ("_InitSSL_str", 0x95129b),
                  ("imac cert.pem", 0x994132)]:
    pat = struct.pack("<Q", val)
    offs = []
    start = 0
    while True:
        i = data.find(pat, start)
        if i < 0: break
        offs.append(i); start = i+1
    print(f"[{name}] raw ptr {val:#x} 出现 {len(offs)} 次: {[hex(o) for o in offs[:10]]}")

# 2. 反汇编 0x551c68 区域
print("\n=== 0x551c40..0x551cc0 ===")
for insn in MD.disasm(data[0x551c40:0x551cc0], 0x551c40):
    mk = ""
    if insn.mnemonic == "bl" and insn.op_str.startswith("#"):
        mk = f"  -> {int(insn.op_str[1:],16):#x}"
    print(f"  {insn.address:#x}: {insn.mnemonic:7s} {insn.op_str}{mk}")
