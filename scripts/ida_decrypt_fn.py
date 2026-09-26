# -*- coding: utf-8 -*-
"""反编译索引解密函数 sub_3AC7CA8 + hash sub_26E236C, 以及 sub_3AC7CA8 调用树。"""
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
    def dec(ea, maxl=400):
        f=ida_funcs.get_func(ea)
        log(f"\n======== sub_{ea:x} ========")
        try:
            txt=str(ida_hexrays.decompile(ea)).splitlines()
            log("\n".join(txt[:maxl]))
            if len(txt)>maxl: log(f"...(+{len(txt)-maxl})")
        except Exception as e:
            log(f"失败 {e}")
        # 直接调用的子函数
        callees=set()
        if f:
            for x in idautils.FuncItems(f.start_ea):
                for r in idautils.XrefsFrom(x,0):
                    t=ida_funcs.get_func(r.to)
                    if t and t.start_ea!=f.start_ea: callees.add(t.start_ea)
        log(f"-- 直接调用: {[hex(c) for c in sorted(callees)][:30]}")
        return callees
    c1=dec(0x3AC7CA8)
    # 下钻 1 层(前4个非库函数)
    for c in sorted(c1)[:4]:
        dec(c, 200)
    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:", OUT)
