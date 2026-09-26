# -*- coding: utf-8 -*-
"""idalib：xref FAES 函数，找调用者（key 来源）。"""
import io, traceback
I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\28_libUnreal_faes.md"
FAES = [0xabf46e4, 0xabf47f8, 0xabf4e70, 0xb6f45c4]

buf=io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")

try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs, ida_hexrays, idc, ida_name, ida_bytes

    callers=set()
    for va in FAES:
        log(f"\n## 调用 FAES 0x{va:x} 的地方")
        for r in idautils.XrefsTo(va):
            f=ida_funcs.get_func(r.frm); fs=f.start_ea if f else 0
            log(f"   <- 0x{r.frm:x}  func@0x{fs:x}")
            if fs: callers.add(fs)
    log(f"\n\n## 调用者函数 {len(callers)} 个:")
    for fs in sorted(callers): log(f"  0x{fs:x}")

    # 反编译前 10 个调用者
    log("\n\n## 调用者反编译（找 key）")
    for i,fs in enumerate(sorted(callers)):
        if i>=10: log("...(截断)"); break
        log(f"\n{'='*60}\n### 0x{fs:x}\n{'='*60}")
        try:
            log(str(ida_hexrays.decompile(fs))[:7000])
        except Exception as e:
            log(f"[失败 {e!r}]")

    # 附加：dump 0xE886B4 附近 0x120 字节（S-box/Rcon 区），看有没有 key 常量紧邻
    log("\n\n## 0xE88600..0xE88800 数据 (S-box/Rcon 区)")
    for a in range(0xE88600, 0xE88800, 16):
        b = ida_bytes.get_bytes(a, 16)
        log(f"  {a:x}: {b.hex() if b else '?'}")

    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:",OUT)
