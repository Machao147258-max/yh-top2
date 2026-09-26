import idc, ida_hexrays, ida_funcs, ida_bytes
idc.auto_wait()
OUT=r"C:\Users\20751\Desktop\异环\reports\ida_libtprt.txt"
f=open(OUT,"w",encoding="utf-8",errors="replace")
f.write("=== libtprt 关键函数反编译 (IDA idat) ===\n")
tg=[("JNI_OnLoad",0x2641c),("initialize",0x25ae0),("ioctl",0x136d7c),
    ("gp6ioctl",0x26058),("gp7ioctl",0x25ea4),("handleLoad",0x135544),
    ("unwind_xx_info_query",0xba814),("strgetter_111740",0x111740),
    ("msgbuild_136F24",0x136f24),("msgparse_137018",0x137018),
    ("initcore_C3764",0xc3764),("sub_128A48",0x128a48)]
# imagebase 归一: 若模块被重定位, 取 min ea
base=0
for name,ea in tg:
    a=ea if base==0 else ea
    f.write("\n==== %s @0x%x ====\n"%(name,a))
    try:
        cf=ida_hexrays.decompile(a)
        f.write(str(cf) if cf else "(no decompile)\n")
    except Exception as e:
        f.write("decomp err: %s\n"%e)
# 另: 列出被调用的函数名(交叉)
f.write("\n=== 文本区读文件相关字符串 xref ===\n")
for s in ["/proc","cmdline","su","ptrace","frida","enable.log","getppid","tprt"]:
    ea=idc.get_name_ea_simple(s)
f.close()
idc.qexit(0)
