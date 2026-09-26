"""
Qiling 直接调用 sub_46AA74 (SSL_write 包装)
- 跳过崩溃的 ELF entry
- 用合成上下文，观察它读取的偏移和 BL 调用
"""
import sys
sys.path.insert(0, r"D:\qiling\qiling-master")

from qiling import Qiling
from qiling.const import QL_VERBOSE

so_path = r"D:\qiling\work\libmxcore.so"
rootfs  = r"D:\qiling\rootfs\rootfs-master\arm64_android"

ql = Qiling([so_path], rootfs=rootfs, verbose=QL_VERBOSE.DISABLED)
base = ql.loader.load_address
print(f"[+] load_address = {hex(base)}")

FUNC_SSLWRITE = base + 0x46AA74
print(f"[+] sub_46AA74 @ {hex(FUNC_SSLWRITE)}")

# --- 读 rodata 确认可访问 ---
try:
    s = ql.mem.read(base + 0x96e148, 60)
    print(f"[+] rodata@0x96e148: {s.split(b'\\x00')[0][:50]}")
except Exception as e:
    print(f"[!] rodata read fail: {e}")

# --- 分配合成内存 ---
SCRATCH = 0x60000000
ql.mem.map(SCRATCH, 0x20000)
SENTINEL = 0x61000000
ql.mem.map(SENTINEL, 0x1000)

# 合成 SSL 上下文: ctx 基址
ctx      = SCRATCH + 0x1000
# [ctx + 0x2A0 + idx*0x28] -> obj ; [obj+8] -> inner
obj      = SCRATCH + 0x8000
inner    = SCRATCH + 0x9000
buf      = SCRATCH + 0x10000
outptr   = SCRATCH + 0x11000

ql.mem.write(ctx + 0x2A0, ql.pack64(obj))
ql.mem.write(obj + 8,      ql.pack64(inner))
ql.mem.write(buf, b"HELLO_SSL_WRITE_TEST\x00")

# 栈
SP = 0x7ffffffd0000 + 0x4000
ql.arch.regs.sp = SP
ql.arch.regs.x0 = ctx
ql.arch.regs.x1 = 0            # idx = 0
ql.arch.regs.x2 = buf
ql.arch.regs.x3 = len(b"HELLO_SSL_WRITE_TEST")   # len
ql.arch.regs.x4 = outptr
ql.arch.regs.x30 = SENTINEL    # 返回哨兵

# --- hooks ---
trace = []
def on_code(ql, addr, size):
    if len(trace) < 120:
        insn = ql.mem.read(addr, min(size, 4))
        trace.append((addr - base, insn.hex()))
    return

def hook_bl_489DBC(ql):
    print(f"    >>> BL sub_489DBC (write)  x0={hex(ql.arch.regs.x0)} x1={hex(ql.arch.regs.x1)} x2={hex(ql.arch.regs.x2)}")
    ql.arch.regs.x0 = 8   # mock: 写了 8 字节
    ql.arch.regs.pc = ql.arch.regs.x30  # 模拟返回

ql.hook_code(on_code)
ql.hook_address(hook_bl_489DBC, base + 0x489DBC)

print("[*] 开始执行 sub_46AA74 ...")
try:
    ql.emu_start(FUNC_SSLWRITE, SENTINEL, timeout=5*1000000, count=5000)
    print("[+] 返回到哨兵，执行结束")
    print(f"[+] 结果 w0 = {hex(ql.arch.regs.w0)}")
except Exception as e:
    print(f"[!] 中止: {type(e).__name__}: {e}")
    print(f"[!] 最后 pc = {hex(ql.arch.regs.pc)}")

print("\n[*] 执行轨迹 (func内偏移):")
for off, ins in trace:
    print(f"    +{off:#x}: {ins}")
