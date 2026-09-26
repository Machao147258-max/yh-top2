# -*- coding: utf-8 -*-
"""反汇编 sub_3AC7CA8, 解析所有 bl 目标 + 引用的全局地址。"""
import traceback
I64=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
try:
    import idapro, idautils, ida_funcs, ida_bytes, ida_ua
    idapro.open_database(I64, False)
    import ida_name
    def dump(ea, tag):
        f=ida_funcs.get_func(ea)
        if not f:
            print(f"\n### {tag} 0x{ea:x} 非函数起始; 所在函数=0x{ida_funcs.get_func(ea).start_ea if ida_funcs.get_func(ea) else 0:x}")
            return None
        print(f"\n### {tag} sub_{f.start_ea:x}  范围 [0x{f.start_ea:x}..0x{f.end_ea:x}] size={f.end_ea-f.start_ea}")
        calls=set(); globs=set()
        for x in idautils.FuncItems(f.start_ea):
            for r in idautils.XrefsFrom(x,0):
                if r.iscode:
                    t=ida_funcs.get_func(r.to)
                    if t: calls.add(t.start_ea)
                else:
                    globs.add(r.to)
        print("  调用目标:", [f"sub_{c:x}" for c in sorted(calls)])
        print(f"  引用全局({len(globs)}):", [f"0x{g:x}" for g in sorted(globs)][:40])
        return calls
    # 先确认函数
    import ida_funcs as F
    for a in (0x3AC7CA8,):
        f=F.get_func(a)
        print(f"0x{a:x}: func={'yes' if f else 'no'} start=0x{f.start_ea:x} " if f else f"0x{a:x}: 无函数")
    calls = dump(0x3AC7CA8, "索引解密函数")
    # 下钻
    if calls:
        for c in sorted(calls)[:5]:
            dump(c, "  子")
    idapro.close_database()
except Exception:
    print("异常:\n"+traceback.format_exc())
