# -*- coding: utf-8 -*-
"""带重试的 DB 打开 + hexrays 初始化诊断。"""
import time, traceback
I64=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
import idapro, ida_hexrays, ida_funcs, idaapi, idautils
for attempt in range(5):
    print(f"\n=== 尝试 {attempt} ===")
    try:
        r = idapro.open_database(I64, attempt>=3)   # 后几次允许自动分析
        print("open_database ->", r)
        ok = ida_hexrays.init_hexrays_plugin()
        print("init_hexrays_plugin ->", ok)
        f = ida_funcs.get_func(0x3ADA03C)
        print("get_func(0x3ADA03C):", hex(f.start_ea) if f else None)
        if ok and f:
            cf = ida_hexrays.decompile(0x3ADA03C)
            print("decompile:", "OK" if cf else "None", (len(str(cf).splitlines()) if cf else 0), "行")
            # 列函数数量
            n=sum(1 for _ in idautils.Functions())
            print("函数总数:", n)
            idapro.close_database()
            break
        idapro.close_database()
    except Exception:
        print("异常:", traceback.format_exc())
    time.sleep(2)
