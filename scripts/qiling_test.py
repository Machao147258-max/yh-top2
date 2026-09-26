"""Qiling 测试 libmxcore.so — 看能不能过 init_array"""
from qiling import Qiling
from pathlib import Path

so_path = r"C:\Users\20751\Desktop\异环\unpacked\so\libmxcore.so"
print(f"[*] Qiling 加载: {so_path}")

# Qiling 需要 android rootfs，先简单测试裸加载
try:
    ql = Qiling([so_path], 
                rootfs=r"D:\qiling\qiling-master\examples\rootfs\arm64_android",
                verbose=True)
    ql.run()
    print("[+] 执行完成")
except Exception as e:
    print(f"[!] 错误: {e}")