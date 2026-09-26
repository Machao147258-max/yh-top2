"""Qiling bare-metal 模式 — 不依赖 rootfs"""
from qiling import Qiling
from qiling.const import QL_VERBOSE

so_path = r"C:\Users\20751\Desktop\异环\unpacked\so\libmxcore.so"
print(f"[*] Qiling {Qiling.__module__}")

# bare-metal 模式: 只需 so 本身，不需要 rootfs
try:
    ql = Qiling([so_path], verbose=QL_VERBOSE.DISABLED)
    print(f"[+] 加载成功: {ql.loader}")
    print(f"[+] 入口: {hex(ql.loader.entry_point)}")
except Exception as e:
    print(f"[!] 加载失败: {e}")
    print("\n需要 rootfs，建议你手动下:")
    print("  git clone https://github.com/qilingframework/qiling.git")
    print("  然后把 examples/rootfs/arm64_android/ 复制到 D:\\qiling\\rootfs\\")