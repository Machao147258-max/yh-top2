# -*- coding: utf-8 -*-
"""探测 idalib(idapro) 是否可用。"""
import sys
try:
    import idapro
    print("idapro 导入成功")
    print("  version:", getattr(idapro, "__version__", "?"))
    print("  attrs:", [a for a in dir(idapro) if not a.startswith("__")][:40])
except Exception as e:
    print("idapro 不可用:", repr(e))

# 顺便看看 IDA 目录
import os
for p in [r"D:\IDA Pro 9.4.260714", r"D:\逆向工具\IDA"]:
    print(p, "存在" if os.path.exists(p) else "不存在")
