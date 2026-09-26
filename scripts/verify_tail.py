from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
SO = r"D:\qiling\work\libmxcore.so"
data = open(SO, "rb").read()
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def s_at(v):
    e = data.find(b"\x00", v)
    return data[v:e].decode('latin1','replace')
for v in [0x951309, 0x951340, 0x95139a, 0x9512eb, 0x9512d6, 0x9512e0]:
    print(f"  {v:#x}: {s_at(v)!r}")

print("\n=== 0x2bbb40..0x2bbbb0 (回调尾部/返回值) ===")
for insn in MD.disasm(data[0x2bbb40:0x2bbbb0], 0x2bbb40):
    mk=""
    if insn.mnemonic=="bl" and insn.op_str.startswith("#"):
        mk=f"  ; -> {int(insn.op_str[1:],16):#x}"
    print(f"  {insn.address:#x}: {insn.mnemonic:7s} {insn.op_str}{mk}")
