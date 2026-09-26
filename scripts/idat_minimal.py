"""idat 最简分析 — 9.4 兼容"""
import sys, os, idc, ida_auto, idautils

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(idc.get_input_file_path())
    base = os.path.splitext(os.path.basename(idc.get_input_file_path()))[0]
    
    ida_auto.auto_wait()
    
    lines = []
    lines.append(f"# {base} — idat 分析\n\n")
    
    # 基本信息
    proc = idc.get_inf_attr(idc.INF_PROCNAME)
    lines.append(f"处理器: {proc}\n")
    
    # 段
    segs = []
    for i in range(100):
        try:
            seg = idc.getnseg(i)
            if seg:
                segs.append(f"{idc.get_segm_name(seg)} {hex(seg.start_ea)}-{hex(seg.end_ea)}")
        except:
            break
    lines.append(f"段数: {len(segs)}\n")
    for s in segs:
        lines.append(f"  {s}\n")
    
    # JNI 导出
    java = []
    named = []
    for ea, name in idautils.Names():
        if "Java_" in name:
            java.append((ea, name))
        elif not name.startswith("sub_") and not name.startswith("loc_"):
            named.append((ea, name))
    
    lines.append(f"\nJNI 导出 ({len(java)}):\n")
    for ea, n in java:
        lines.append(f"  {hex(ea)} {n}\n")
    
    lines.append(f"\n其他命名 ({len(named)}):\n")
    for ea, n in named[:30]:
        lines.append(f"  {hex(ea)} {n}\n")
    
    # 只搜少数字符串
    for kw in ["JNI_OnLoad", "SSL_write", "SSL_read", "sm4", "Friday", "ptrace"]:
        try:
            ea = idc.get_name_ea_simple(kw)
            if ea != 0xFFFFFFFF:
                xrefs = list(idautils.XrefsTo(ea))
                lines.append(f"\n{kw} @ {hex(ea)} ({len(xrefs)} refs)\n")
        except:
            pass
    
    lines.append(f"\n总命名符号: {len(list(idautils.Names()))}\n")
    
    rp = os.path.join(out, f"{base}_idat.md")
    with open(rp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print(f"[+] {rp}")
    idc.qexit(0)

main()