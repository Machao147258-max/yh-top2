"""idat 找 SSL_write 交叉引用 — 只做这一件事"""
import sys, os, idc, ida_auto, idautils, ida_segment

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(idc.get_input_file_path())
    rp = os.path.join(out, "ssl_xref.md")
    
    ida_auto.auto_wait()
    
    lines = []
    lines.append("# libmxcore SSL_write/SSL_read 交叉引用\n\n")
    
    for target in ["SSL_write", "SSL_read"]:
        lines.append(f"## 搜索: {target}\n\n")
        
        # 找字符串
        ea = idc.get_name_ea_simple(target)
        if ea == 0xFFFFFFFF:
            # 可能不是符号名，尝试搜字符串
            lines.append(f"符号 {target} 未找到，搜索字符串...\n")
            for seg_ea in idautils.Segments():
                sname = ida_segment.get_segm_name(seg_ea)
                if sname in (".rodata", ".data", ".rdata"):
                    for addr in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                        try:
                            if idc.is_strlit(idc.get_full_flags(addr)):
                                s = idc.get_strlit_contents(addr)
                                if s and target.encode() in s:
                                    lines.append(f"字符串 '{target}' @ {hex(addr)}\n")
                                    ea = addr
                                    break
                        except:
                            pass
            if ea == 0xFFFFFFFF:
                lines.append(f"未找到\n\n")
                continue
        
        # 找交叉引用
        if ea != 0xFFFFFFFF:
            try:
                xrefs = list(idautils.XrefsTo(ea))
                lines.append(f"字符串 @ {hex(ea)}\n")
                lines.append(f"引用数: {len(xrefs)}\n\n")
                
                if xrefs:
                    lines.append("| 调用地址 | 所属函数 | 指令 |\n")
                    lines.append("| --- | --- | --- |\n")
                    for x in xrefs[:20]:
                        caller_func = idc.get_func_name(x.frm) or "?"
                        try:
                            disasm = idc.generate_disasm_line(x.frm, 0)
                        except:
                            disasm = "?"
                        lines.append(f"| {hex(x.frm)} | {caller_func} | {disasm} |\n")
                    
                    if len(xrefs) > 20:
                        lines.append(f"| ... 还有 {len(xrefs)-20} 处 | | |\n")
            except Exception as e:
                lines.append(f"xref 错误: {e}\n")
        
        lines.append("\n")
    
    with open(rp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    
    print(f"[+] {rp}")
    idc.qexit(0)

main()