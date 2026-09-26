# -*- coding: utf-8 -*-
"""idalib：找 crypto 相关函数 + 反编译 pak 索引解密辅助。"""
import io, re, traceback
I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\26_libUnreal_crypt.md"
HELPERS = [0x3ADBA88, 0x3ADBB30, 0x3ADC314, 0x3ADB1D4, 0x3ADB808]

buf=io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")

try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs, ida_hexrays, idc, ida_name

    # 1) crypto 相关函数名
    pat = re.compile(r"(Decrypt|Encrypt|AES|FAES|Crypt|_Key|Key_|PakSign|Signing|SHA|MD5|Blowfish)", re.I)
    log("## 名字含 crypto 的函数")
    cnt=0
    for ea, nm in idautils.Names():
        if pat.search(nm):
            f = ida_funcs.get_func(ea)
            log(f"  0x{ea:x}  {nm}   (func@{'0x%x'%f.start_ea if f else '-'})")
            cnt+=1
            if cnt>200: log("  ...(截断)"); break
    log(f"  （共 {cnt} 个）")

    # 2) 反编译 pak 索引辅助
    log("\n\n## pak 索引辅助函数反编译")
    for va in HELPERS:
        log(f"\n{'='*60}\n### 0x{va:x}\n{'='*60}")
        try:
            cf = ida_hexrays.decompile(va)
            log(str(cf) if cf else "[空]")
        except Exception as e:
            log(f"[失败 {e!r}] 退反汇编:")
            ea=va
            for _ in range(150):
                log(f"  {ea:x}: {idc.GetDisasm(ea)}"); ea=idc.next_head(ea)

    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:",OUT)
