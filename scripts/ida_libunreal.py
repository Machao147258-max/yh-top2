# -*- coding: utf-8 -*-
"""idalib：打开 libUnreal.so.i64 -> 总览 -> 关键串 xref（IoStore/AES/Oodle）。"""
import sys, io, traceback

I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\24_libUnreal_ida.md"

TARGET_SUBSTR = ["DirectoryIndex", "IoStore", "Oodle", "OodleLZ_Decompress",
                 "EncryptionKey", "AES", "FAES", "DecryptData", "Crypto",
                 "TocHeader", "PakFile", "Decrypt", "IoStorage"]

buf = io.StringIO()
def log(*a):
    s = " ".join(str(x) for x in a)
    print(s); buf.write(s + "\n")

try:
    import idapro
    log("== idapro 版本:", getattr(idapro, "get_library_version", lambda: "?")())
    log("== 打开数据库:", I64)
    idapro.open_database(I64, False)   # 不重跑自动分析
    log("== 打开完成")

    import idautils, ida_funcs, ida_bytes, idc, ida_segment, ida_name, ida_nalt, ida_entry

    # 段
    log("\n## 段")
    for seg_ea in idautils.Segments():
        s = ida_segment.getseg(seg_ea)
        log(f"  {ida_segment.get_segm_name(s)}  start=0x{seg_ea:x} end=0x{s.end_ea:x}")

    # 函数计数
    funcs = list(idautils.Functions())
    log(f"\n## 函数总数: {len(funcs)}")

    # 字符串 xref
    log("\n## 关键字符串 xref")
    n_str = 0
    hits = {t: [] for t in TARGET_SUBSTR}
    for s in idautils.Strings():
        try:
            v = str(s)
        except Exception:
            continue
        n_str += 1
        for t in TARGET_SUBSTR:
            if t in v:
                ea = s.ea
                refs = []
                for r in idautils.XrefsTo(ea):
                    f = ida_funcs.get_func(r.frm)
                    fn = ida_name.get_name(f.start_ea) if f else ""
                    refs.append((r.frm, f.start_ea if f else 0, fn))
                hits[t].append((ea, v[:80], refs))
    log(f"  （共扫描字符串 {n_str} 条）")
    for t in TARGET_SUBSTR:
        if hits[t]:
            log(f"\n### {t}  ({len(hits[t])} 条)")
            for ea, v, refs in hits[t][:15]:
                log(f"  str@0x{ea:x}: {v!r}")
                for frm, fstart, fn in refs[:6]:
                    log(f"      <- 0x{frm:x}  func@0x{fstart:x} {fn}")

    import idapro
    idapro.close_database()
    log("\n== 关闭完成")
except Exception:
    log("异常:\n" + traceback.format_exc())

open(OUT, "w", encoding="utf-8").write(buf.getvalue())
print("写出:", OUT)
