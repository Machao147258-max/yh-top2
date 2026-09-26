# -*- coding: utf-8 -*-
"""idalib：反编译关键函数（pak索引/Oodle/网络），输出伪代码。"""
import io, traceback

I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\25_libUnreal_decomp.md"

TARGETS = [
    (0x3ada03c, "PakFile index (Load/Hash DirectoryIndex)"),
    (0x3ad9050, "PakFile_LoadLegacy"),
    (0x3ad7e8c, "PakFile_SerilizeTrailer"),
    (0xb587284, "OodleLZ_Decompress wrapper"),
    (0xb587180, "Oodle (legacy check)"),
    (0xb588538, "OodleLZ_Compress wrapper"),
    (0x5d79a9c, "IoStoreOnDemandCore"),
    (0x3a5b660, "OnDemandHttpClient"),
    (0x2545c8c, "FIoStore (IoStore)"),
]

buf = io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")

try:
    import idapro
    idapro.open_database(I64, False)
    import ida_funcs, ida_hexrays, ida_bytes, idc, ida_name, idaapi

    def decomp(va):
        f = ida_funcs.get_func(va)
        if not f:
            return f"[未找到函数 @0x{va:x}]"
        try:
            cf = ida_hexrays.decompile(va)
            return str(cf) if cf else "[decompile 返回空]"
        except Exception as e:
            # 退回反汇编
            out=[]
            ea=va
            for i in range(120):
                d=idc.GetDisasm(ea); out.append(f"{ea:x}: {d}")
                ea=idc.next_head(ea)
            return "[hexrays 失败: %r]\n" % e + "\n".join(out)

    for va, desc in TARGETS:
        log(f"\n\n{'='*70}\n## 0x{va:x}  {desc}\n{'='*70}")
        log(decomp(va))

    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())

open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:", OUT)
