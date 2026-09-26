"""Qiling 加载 libmxcore.so — 纯英文路径"""
import sys
sys.path.insert(0, r"D:\qiling\qiling-master")

from qiling import Qiling
from qiling.const import QL_VERBOSE

so_path = r"D:\qiling\work\libmxcore.so"
rootfs = r"D:\qiling\rootfs\rootfs-master\arm64_android"

print(f"[*] 加载: {so_path}")
try:
    ql = Qiling([so_path], rootfs=rootfs, verbose=QL_VERBOSE.DEFAULT)
    print("[+] 初始化 OK")
    print(f"[+] entry: {hex(ql.loader.entry_point)}")
    ql.run()
    print("[+] 完成")
except Exception as e:
    import traceback
    traceback.print_exc()