# -*- coding: utf-8 -*-
"""找所有调用 AES 类 (SetKey 0xABFA760 / Dec 0xABFA8E0 / Enc 0xABFA9A8) 的地方。"""
import traceback
I64=r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
TGT={0xABFA760:"SetKey",0xABFA8E0:"Dec",0xABFA9A8:"Enc",
     0xABF46E4:"KeyExp",0xB587284:"Oodle.Decompress",0xB587180:"Oodle.Check"}
try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs
    for t,name in TGT.items():
        print(f"\n=== 调用 {name} (0x{t:x}) ===")
        n=0
        for x in idautils.XrefsTo(t, 0):
            fn=ida_funcs.get_func(x.frm)
            caller=fn.start_ea if fn else 0
            kind = "调用" if x.type in (16,17,18,19,21) else f"type={x.type}"
            print(f"  0x{x.frm:x} [{kind}]  in sub_{caller:x}")
            n+=1
            if n>=40: print("  ..."); break
        if n==0: print("  (无直接 xref)")
    idapro.close_database()
except Exception:
    print("异常:\n"+traceback.format_exc())
