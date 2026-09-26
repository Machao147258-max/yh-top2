"""补环境 + hook: 用 harness 跑 CT::SSLContext::_InitSSL"""
import sys
sys.path.insert(0, r"D:\qiling\qiling-master")
sys.path.insert(0, r"C:\Users\20751\Desktop\异环\scripts")
from qiling_harness import Harness, HEAP_BASE, SO, ROOTFS

h = Harness(SO, ROOTFS)
ql = h.ql

# 独立内存区放 TLS / this (避免与 malloc 堆碰撞)
AUX = 0x52000000
ql.mem.map(AUX, 0x10000)
TLS = AUX            # TLS 块
this = AUX + 0x8000  # SSLContext 对象
ql.mem.write(TLS, b"\x00" * 0x2000)
ql.mem.write(TLS + 0x28, ql.pack64(0xA1B2C3D4E5F60718))   # __stack_chk_guard
try:
    from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
    ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    print(f"[*] tpidr_el0 = {ql.uc.reg_read(UC_ARM64_REG_TPIDR_EL0):#x}")
except Exception as e:
    print(f"[!] tpidr_el0 失败: {e}")

def hook(name, addr):
    def cb(q):
        r = q.arch.regs
        print(f"    [{name}] @{addr:#x}  x0={r.x0:#x} x1={r.x1:#x} x2={r.x2:#x} x3={r.x3:#x}")
    ql.hook_address(cb, h.base + addr)

hook("SSL_CTX_obj", 0x48b0e0)
hook("FAIL_ctx_3bc", 0x48b3bc)
hook("FAIL_ctx_398", 0x48b398)
hook("FAIL_ctx_3d4", 0x48b3d4)
hook("TLS_method", 0x476cdc)
hook("OPENSSL_init", 0x4868d0)
hook("crypto_zalloc", 0x518b10)
hook("SSL_new", 0x487020)
hook("SSL_set_bio", 0x488b0c)
hook("set_verify", 0x48b52c)
hook("get_version", 0x48b758)
hook("ver_str", 0x48bcec)
hook("connect_state", 0x4893f0)
hook("accept_state", 0x48959c)

ql.mem.write(this, b"\x00" * 0x100)
ql.mem.write(this + 0x38, ql.pack32(0))   # 模式=0 (客户端)
# 诊断: 强制让 OPENSSL_init 的失败分支不成立 (w0=1)
ql.hook_address(lambda q: setattr(q.arch.regs, "x0", 1), h.base + 0x486924)
print(f"[*] this = {this:#x}")
print("[*] 调用 _InitSSL(this) ...\n")
try:
    h.call(0x2BB570, [this], max_insn=500000, timeout_us=30_000_000)
    print("\n[+] 返回")
except Exception as e:
    print(f"\n[!] {type(e).__name__}: {e}  pc={ql.arch.regs.pc:#x} (off={ql.arch.regs.pc - h.base:#x})")

print(f"\n[结果] this+0x08 (SSL_CTX?) = {ql.unpack64(ql.mem.read(this+8,8)):#x}")
print(f"[结果] this+0x10 (SSL?)     = {ql.unpack64(ql.mem.read(this+0x10,8)):#x}")
print(f"[结果] this+0x18 (BIO_r?)   = {ql.unpack64(ql.mem.read(this+0x18,8)):#x}")
print(f"[结果] this+0x20 (BIO_w?)   = {ql.unpack64(ql.mem.read(this+0x20,8)):#x}")
print(f"[结果] this+0x28 (inited)   = {ql.mem.read(this+0x28,1)[0]}")
