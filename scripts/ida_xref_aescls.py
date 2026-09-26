# -*- coding: utf-8 -*-
"""idalib：xref AES 类(SetKey/Enc/Dec)，找 key 来源。"""
import io, traceback
I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\29_libUnreal_aeskey.md"
SETKEY=0xabfa760; DEC=0xabfa8e0; ENC=0xabfa9a8

buf=io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")

try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs, ida_hexrays, idc

    callers=set()
    for va,nm in [(SETKEY,"SetKey"),(DEC,"Decrypt"),(ENC,"Encrypt")]:
        log(f"\n## 调用 AES::{nm} (0x{va:x})")
        for r in idautils.XrefsTo(va):
            f=ida_funcs.get_func(r.frm); fs=f.start_ea if f else 0
            log(f"   <- 0x{r.frm:x}  func@0x{fs:x}")
            if fs: callers.add((fs,nm))

    log(f"\n\n## 调用者函数（{len(callers)}）:")
    seen=set()
    for fs,nm in sorted(callers):
        if fs in seen: continue
        seen.add(fs)
        log(f"  0x{fs:x}   (via {nm})")

    log("\n\n## 反编译调用者（找 16 字节 key 常量）")
    for i,fs in enumerate(sorted(seen)):
        if i>=12: log("...(截断)"); break
        log(f"\n{'='*60}\n### 0x{fs:x}\n{'='*60}")
        try:
            log(str(ida_hexrays.decompile(fs))[:6500])
        except Exception as e:
            log(f"[失败 {e!r}]")
    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:",OUT)
