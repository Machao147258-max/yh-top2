# -*- coding: utf-8 -*-
"""定位包含 0x3AC7CA8 的函数并反编译; 同时列出 0x3AC7xxx 附近函数。"""
import io, traceback
I64=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT=r"C:\Users\20751\Desktop\异环\reports\36_pak_decrypt_fn.md"
buf=io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")
try:
    import idapro, idautils, ida_funcs, ida_hexrays
    idapro.open_database(I64, False)
    ida_hexrays.init_hexrays_plugin()
    # 列函数
    fs=[f for f in idautils.Functions(0x3AC7000, 0x3AC9000)]
    log("附近函数:")
    for f in sorted(fs):
        log(f"  0x{f:x}")
    # 谁包含 0x3AC7CA8
    import idaapi
    f=idaapi.get_func(0x3AC7CA8)
    log(f"\nget_func(0x3AC7CA8) = {hex(f.start_ea) if f else None}")
    # 反编译调用者 sub_3ADA03C 中该分支
    log("\n==== 反编译 sub_3ADA03C 全文 ====")
    try:
        log(str(ida_hexrays.decompile(0x3ADA03C)))
    except Exception as e:
        log(f"失败 {e}")
    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:", OUT)
