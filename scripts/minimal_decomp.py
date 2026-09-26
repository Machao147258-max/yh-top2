# -*- coding: utf-8 -*-
"""最小测试: 打开 DB, 反编译一个已知函数。"""
import traceback
I64=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
try:
    import idapro
    print("open...")
    r=idapro.open_database(I64, False)
    print("open_database ->", r)
    import ida_hexrays, ida_funcs, idaapi
    ok=ida_hexrays.init_hexrays_plugin()
    print("init_hexrays_plugin ->", ok)
    print("hexrays available:", ida_hexrays.hexrays_available())
    f=ida_funcs.get_func(0x3ADA03C)
    print("get_func(0x3ADA03C):", hex(f.start_ea) if f else None)
    g=idaapi.get_func(0x3ADA03C)
    print("idaapi.get_func:", hex(g.start_ea) if g else None)
    cf=ida_hexrays.decompile(0x3ADA03C)
    print("decompile type:", type(cf))
    if cf: print("行数:", len(str(cf).splitlines()))
    # 试 0x3AC7CA8
    print("\n--- 0x3AC7CA8 ---")
    f2=ida_funcs.get_func(0x3AC7CA8)
    print("get_func:", hex(f2.start_ea) if f2 else None)
    idapro.close_database()
except Exception:
    print("异常:\n"+traceback.format_exc())
