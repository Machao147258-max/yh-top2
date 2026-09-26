"""idat 精准分析: 已知虚址 0x96e148/0x96dce0，直接找 xref"""
import sys, os, idc, ida_auto, idautils, ida_bytes

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(idc.get_input_file_path())
    rp = os.path.join(out, "ssl_xref_precise.md")
    
    ida_auto.auto_wait()
    
    lines = []
    lines.append("# libmxcore SSL_write/SSL_read — 精准 xref\n\n")
    
    targets = {
        "SSL_write": 0x96e148,
        "SSL_read":  0x96dce0,
    }
    
    for name, addr in targets.items():
        lines.append(f"## {name}\n\n")
        lines.append(f"- 虚址: {hex(addr)}\n")
        
        # 检查该地址的类型
        flags = ida_bytes.get_full_flags(addr)
        is_str = ida_bytes.is_strlit(flags)
        lines.append(f"- IDA 识别为字符串: {'✅' if is_str else '❌'}\n")
        
        if not is_str:
            # 手动标记为字符串
            try:
                ida_bytes.create_strlit(addr, 0, idc.ALOPT_IGNHEADS)
                lines.append(f"- 已强制标记为字符串\n")
                flags = ida_bytes.get_full_flags(addr)
                is_str = ida_bytes.is_strlit(flags)
                lines.append(f"- 标记后: {'✅' if is_str else '❌'}\n")
            except Exception as e:
                lines.append(f"- 标记失败: {e}\n")
        
        # 读该地址的内容确认
        try:
            content = idc.get_strlit_contents(addr)
            if content:
                lines.append(f"- 内容: {content.decode('utf-8', errors='replace')[:50]}\n")
        except:
            pass
        
        # 找 xref
        try:
            xrefs = list(idautils.XrefsTo(addr))
            lines.append(f"- xref 数量: {len(xrefs)}\n\n")
            
            if xrefs:
                lines.append("| 调用地址 | 所属函数 | 指令 |\n")
                lines.append("| --- | --- | --- |\n")
                for x in xrefs[:30]:
                    func = idc.get_func_name(x.frm) or "?"
                    try:
                        disasm = idc.generate_disasm_line(x.frm, 0)
                    except:
                        disasm = "?"
                    lines.append(f"| {hex(x.frm)} | {func} | {disasm} |\n")
                if len(xrefs) > 30:
                    lines.append(f"| ... 还有 {len(xrefs)-30} 处 | | |\n")
            else:
                lines.append("无 xref（IDA 未建立引用，需进一步分析）\n")
        except Exception as e:
            lines.append(f"- xref 错误: {e}\n")
        
        lines.append("\n")
    
    with open(rp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    
    print(f"[+] {rp}")
    idc.qexit(0)

main()