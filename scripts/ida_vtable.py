# -*- coding: utf-8 -*-
"""idalib：dump AES 虚表 + xref 使用者。"""
import io, traceback
I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\30_libUnreal_vtable.md"
buf=io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")
try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs, ida_hexrays, ida_bytes, idc, ida_name

    base=0xdfaf6c0
    log("## 虚表区域 0xdfaf6c0..0xdfaf760")
    vtaddrs=[]
    for a in range(base, 0xdfaf760, 8):
        v=ida_bytes.get_qword(a)
        nm=ida_name.get_name(v) or ""
        log(f"  {a:x}: 0x{v:x}  {nm}")
        if 0xabf0000<=v<=0xac00000 or 0xb000000<v:
            vtaddrs.append((a,v))

    log("\n## xref 虚表内函数指针指向的函数")
    for a,v in vtaddrs:
        log(f"\n### slot {a:x} -> 0x{v:x}")
        for r in idautils.XrefsTo(v):
            f=ida_funcs.get_func(r.frm); fs=f.start_ea if f else 0
            log(f"   <- 0x{r.frm:x} func@0x{fs:x}")

    # 找引用虚表基址的代码：xref 每个 slot 地址
    log("\n## xref 虚表地址本身（谁引用了 vtable）")
    for a,_ in vtaddrs[:4]:
        n=0
        for r in idautils.XrefsTo(a):
            f=ida_funcs.get_func(r.frm); fs=f.start_ea if f else 0
            log(f"  vt {a:x} <- 0x{r.frm:x} func@0x{fs:x}"); n+=1
        if n==0: log(f"  vt {a:x}: 无 xref")

    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:",OUT)
