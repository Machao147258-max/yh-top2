# -*- coding: utf-8 -*-
"""idalib：xref AES 表，定位 AES/FAES 函数。"""
import io, traceback
I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\27_libUnreal_aes.md"
AES_ADDRS = [0xce3bb0, 0xce4cb0, 0xce2bb0, 0xe886b4, 0xe887bf, 0xe887b5, 0xf447c8]

buf=io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")

try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs, ida_hexrays, idc, ida_name

    funcs = {}
    for va in AES_ADDRS:
        log(f"\n## xref AES 表 0x{va:x}")
        for r in idautils.XrefsTo(va):
            f = ida_funcs.get_func(r.frm)
            fs = f.start_ea if f else 0
            log(f"   <- 0x{r.frm:x}  func@0x{fs:x}")
            if fs: funcs[fs]=1
    log(f"\n\n## 涉及 AES 的函数（{len(funcs)} 个）：")
    for fs in sorted(funcs):
        log(f"  0x{fs:x}  {ida_name.get_name(fs)}")

    # 试着反编译每个（限前 12 个，避免过大）
    log("\n\n## 反编译 AES 相关函数")
    for i, fs in enumerate(sorted(funcs)):
        if i >= 12: log("  ...(截断)"); break
        log(f"\n{'='*60}\n### 0x{fs:x}\n{'='*60}")
        try:
            cf = ida_hexrays.decompile(fs)
            log(str(cf)[:6000] if cf else "[空]")
        except Exception as e:
            log(f"[反编译失败 {e!r}]")
    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:",OUT)
