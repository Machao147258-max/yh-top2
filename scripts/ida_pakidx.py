# -*- coding: utf-8 -*-
"""反编译 pak 索引加载器 sub_3ADA03C 及其调用树。"""
import io, traceback
I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\35_pak_index_decomp.md"
START = 0x3ADA03C
buf=io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")
try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs, ida_hexrays, idaapi
    ida_hexrays.init_hexrays_plugin()
    seen=set()
    def dump(ea, depth):
        f=ida_funcs.get_func(ea)
        if not f: 
            log("  "*depth+f"(0x{ea:x} 非函数)"); return
        s=f.start_ea
        if s in seen: 
            log("  "*depth+f"(已见 sub_{s:x})"); return
        seen.add(s)
        log("\n"+"  "*depth+f"==== sub_{s:x} ====")
        try:
            cf=ida_hexrays.decompile(s)
            txt=str(cf)
            # 只保留前 120 行避免太大
            lines=txt.splitlines()
            log("\n".join(lines[:120]))
            if len(lines)>120: log(f"  ...(+{len(lines)-120} 行, 截断)")
        except Exception as e:
            log(f"  反编译失败: {e}")
        # 列出被调
        callees=set()
        for x in idautils.XrefsFrom(s, 0):
            t=ida_funcs.get_func(x.to)
            if t and t.start_ea!=s: callees.add(t.start_ea)
        # 只下钻前 6 个
        for i,c in enumerate(sorted(callees)[:6]):
            dump(c, depth+1)
    dump(START, 0)
    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:", OUT)
