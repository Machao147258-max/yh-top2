"""补环境: 先跑 .init_array, 再调用 _InitSSL (带 hook 追踪)"""
import sys
sys.path.insert(0, r"D:\qiling\qiling-master")
sys.path.insert(0, r"C:\Users\20751\Desktop\异环\scripts")
from elftools.elf.elffile import ELFFile
from qiling_harness import Harness, HEAP_BASE, SO, ROOTFS

h = Harness(SO, ROOTFS)
ql = h.ql

AUX = 0x52000000
ql.mem.map(AUX, 0x10000)
TLS = AUX
this = AUX + 0x8000
ql.mem.write(TLS, b"\x00" * 0x8000)
ql.mem.write(TLS + 0x28, ql.pack64(0xA1B2C3D4E5F60718))
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)

elf = ELFFile(open(SO, "rb"))
inits = []
for name in ('.init_array', '.init_array.0'):
    sec = elf.get_section_by_name(name)
    if sec:
        d = sec.data()
        for i in range(0, len(d), 8):
            v = int.from_bytes(d[i:i+8], "little")
            if v: inits.append(v)
print(f"[*] .init_array: {len(inits)} 个")

print("[*] 执行构造函数 ...")
ok = 0
for v in inits:
    try:
        h.call(v, [], max_insn=500000, timeout_us=10_000_000)
        ok += 1
    except Exception as e:
        print(f"    [!] init {v:#x}: {type(e).__name__} off={ql.arch.regs.pc - h.base:#x}")
print(f"    构造函数 OK {ok}/{len(inits)}")

# hooks
def hook(name, addr):
    def cb(q):
        r = q.arch.regs
        print(f"    [{name}] x0={r.x0:#x} x1={r.x1:#x} x2={r.x2:#x}")
    ql.hook_address(cb, h.base + addr)

hook("SSL_CTX_new", 0x48b0e0)
hook("OPENSSL_init", 0x4868d0)
hook("FAIL_3bc", 0x48b3bc)
hook("FAIL_398", 0x48b398)
hook("FAIL_3d4", 0x48b3d4)

def on_log(ql):
    r = ql.arch.regs
    try: fmt = ql.mem.string(r.x1)
    except Exception: fmt = "?"
    print(f"    [LOG fmt] {fmt!r}")
    r.pc = r.x30            # skip 日志函数
ql.hook_address(on_log, h.base + 0xafa68)   # 内部日志

print("\n[*] 调用 _InitSSL(this) ...")
ql.mem.write(this, b"\x00" * 0x100)
ql.mem.write(this + 0x38, ql.pack32(0))
_seq = []
def _trace(q, addr, size):
    off = addr - h.base
    if 0x2bb570 <= off <= 0x2bb780:
        if not _seq or _seq[-1] != off:
            _seq.append(off)
ql.hook_code(_trace)
try:
    h.call(0x2BB570, [this], max_insn=2000000, timeout_us=60_000_000)
    print("[+] _InitSSL 返回")
except Exception as e:
    print(f"[!] {type(e).__name__}: {e}  off={ql.arch.regs.pc - h.base:#x}")
print("[轨迹]", " ".join(f"+{o:#x}" for o in _seq))

print(f"[结果] SSL_CTX [this+8]  = {ql.unpack64(ql.mem.read(this+8,8)):#x}")
print(f"[结果] SSL     [this+10] = {ql.unpack64(ql.mem.read(this+0x10,8)):#x}")
print(f"[结果] BIO_r   [this+18] = {ql.unpack64(ql.mem.read(this+0x18,8)):#x}")
print(f"[结果] BIO_w   [this+20] = {ql.unpack64(ql.mem.read(this+0x20,8)):#x}")
print(f"[结果] inited  [this+28] = {ql.mem.read(this+0x28,1)[0]}")
