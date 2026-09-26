import idaapi
import idc

out = []
out.append("CLI_SCRIPT_OK")
out.append("filename=%s" % idaapi.get_root_filename())
try:
    out.append("min_ea=0x%x max_ea=0x%x" % (idaapi.get_min_ea(), idaapi.get_max_ea()))
except Exception as e:
    out.append("ea_err=%s" % e)
# count functions if any
try:
    import idautils
    n = 0
    for _ in idautils.Functions():
        n += 1
    out.append("functions=%d" % n)
except Exception as e:
    out.append("func_err=%s" % e)
open(r"C:\Users\20751\Desktop\异环\cli_test_out.txt", "w", encoding="utf-8").write("\n".join(out))
idc.qexit(0)