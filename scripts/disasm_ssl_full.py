"""带注释的反汇编: 解析 adrp+add/ldr 目标字符串 + bl 目标"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def s_at(v):
    if v <= 0 or v >= len(data): return None
    e = data.find(b"\x00", v)
    if e < 0 or e - v > 80: return None
    try:
        t = data[v:e].decode('latin1')
        return t if t.isprintable() and len(t) >= 3 else None
    except: return None

def disasm(start, end, label=""):
    print(f"\n===== {label} {start:#x}..{end:#x} =====")
    code = data[start:end]
    insns = list(MD.disasm(code, start))
    for idx, insn in enumerate(insns):
        mk = ""
        if insn.mnemonic == "bl" and insn.op_str.startswith("#"):
            mk = f"  ; bl -> {int(insn.op_str[1:],16):#x}"
        if insn.mnemonic in ("adrp",) and idx+1 < len(insns):
            nxt = insns[idx+1]
            if nxt.mnemonic == "add" and nxt.op_str.endswith(insn.op_str.split(',')[0].strip()):
                # 粗略解析
                pass
        print(f"  {insn.address:#x}: {insn.mnemonic:7s} {insn.op_str}{mk}")

# _InitSSL 全
disasm(0x2bb570, 0x2bb960, "_InitSSL")
# 调用者 1
disasm(0x2bbd80, 0x2bbdf0, "caller@0x2bbdb8")
# 调用者 2
disasm(0x2bbec0, 0x2bbf40, "caller@0x2bbf0c")
# pin 设置点
disasm(0x440c20, 0x440d10, "pin site @0x440cb8")
