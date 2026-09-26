# -*- coding: utf-8 -*-
"""完整反编译 sub_3ADA03C, 并列出所有调用目标(带地址)用于判定 解密/解压/AES/Oodle。"""
import io, traceback
I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
BODY = r"C:\Users\20751\Desktop\异环\reports\35a_idx_loader_body.txt"
CALLS= r"C:\Users\20751\Desktop\异环\reports\35b_idx_loader_calls.txt"
START= 0x3ADA03C
# 关注的地址
KNOWN={0xABFA760:"AES.SetKey",0xABFA8E0:"AES.Dec",0xABFA9A8:"AES.Enc",
       0xB587284:"Oodle.Decompress",0xB588538:"Oodle.Compress",0xB587180:"Oodle.Check",
       0x3ADBB30:"索引hash校验",0x3AD7E8C:"SerilizeTrailer",0x267EF30:"OpenSSL.AES_dec"}
try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs, ida_hexrays
    ida_hexrays.init_hexrays_plugin()
    f=ida_funcs.get_func(START)
    cf=ida_hexrays.decompile(START)
    body=str(cf)
    open(BODY,"w",encoding="utf-8").write(body)
    print(f"函数体 {len(body.splitlines())} 行 -> {BODY}")
    # 调用目标
    lines=[]
    seen=set()
    for ea in idautils.FuncItems(f.start_ea):
        for x in idautils.XrefsFrom(ea, 0):
            t=x.to
            fn=ida_funcs.get_func(t)
            if not fn: continue
            key=(fn.start_ea)
            tag=KNOWN.get(fn.start_ea)
            lines.append(f"0x{ea:x} -> sub_{fn.start_ea:x} [{tag or ''}]")
    open(CALLS,"w",encoding="utf-8").write("\n".join(lines))
    print(f"调用点 {len(lines)} 条 -> {CALLS}")
    # 直接打印命中的关注目标
    for l in lines:
        if "[" in l and l.split("[")[1].strip("] "):
            print("  ", l)
    # 打印函数体里含 Decrypt/Oodle/Key/AES/Decode 的行
    print("\n== body 关键字命中 ==")
    for ln in body.splitlines():
        low=ln.lower()
        if any(k in low for k in ("decrypt","crypt","oodle","decompress","aes","key","decode","hash")):
            print("  ", ln.strip()[:150])
    idapro.close_database()
except Exception:
    print("异常:\n"+traceback.format_exc())
