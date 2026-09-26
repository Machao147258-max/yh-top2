"""idat 追 'Friday' 字符串的 xref — 验证是否为 Frida 检测"""
import sys, os, idc, ida_auto, idautils, ida_bytes, ida_funcs

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(idc.get_input_file_path())
    rp = os.path.join(out, "friday_xref.md")
    
    ida_auto.auto_wait()
    
    lines = []
    lines.append("# 'Friday' 字符串 xref 分析\n\n")
    lines.append("> 目的: 判断是否为 Frida 检测，还是误报\n\n")
    
    # 搜 "Friday" 字符串
    friday_addrs = []
    for seg_ea in idautils.Segments():
        for ea in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
            try:
                if ida_bytes.is_strlit(ida_bytes.get_full_flags(ea)):
                    s = idc.get_strlit_contents(ea)
                    if s and b"Friday" in s:
                        friday_addrs.append((ea, s.decode('utf-8', errors='replace')))
            except:
                pass
    
    lines.append(f"找到 {len(friday_addrs)} 处 'Friday' 字符串:\n\n")
    
    for addr, content in friday_addrs:
        lines.append(f"### @ {hex(addr)}\n")
        lines.append(f"- 内容: `{content[:80]}`\n")
        
        # 找 xref
        try:
            xrefs = list(idautils.XrefsTo(addr))
            lines.append(f"- xref: {len(xrefs)} 处\n")
            
            if xrefs:
                lines.append("\n| 地址 | 所属函数 | 指令 |\n")
                lines.append("| --- | --- | --- |\n")
                for x in xrefs[:10]:
                    func = idc.get_func_name(x.frm) or "?"
                    try:
                        disasm = idc.generate_disasm_line(x.frm, 0)
                    except:
                        disasm = "?"
                    # 如果是 BL，看调了什么
                    lines.append(f"| {hex(x.frm)} | {func} | {disasm} |\n")
                    
                    # 如果是 BL，看目标
                    if "BL" in disasm:
                        parts = disasm.split()
                        if len(parts) > 1:
                            target = parts[-1]
                            lines.append(f"    -> 调用: {target}\n")
                    
                    # 看附近 5 条指令判断上下文
                    lines.append(f"  **上下文:**\n")
                    ctx_count = 0
                    for ea2 in idautils.Heads(max(x.frm-20, 0), x.frm+20):
                        if ctx_count > 8:
                            break
                        try:
                            d = idc.generate_disasm_line(ea2, 0)
                            marker = "  ← ★" if ea2 == x.frm else ""
                            lines.append(f"  {hex(ea2)}: {d}{marker}\n")
                            ctx_count += 1
                        except:
                            pass
        except Exception as e:
            lines.append(f"- xref 错误: {e}\n")
    
    # 判断结论
    lines.append("\n## 结论\n\n")
    total_xrefs = sum(len(list(idautils.XrefsTo(a))) for a, _ in friday_addrs)
    if total_xrefs == 0:
        lines.append("Friday 字符串无 xref，可能是:\n")
        lines.append("- 编译产物中的日期戳（如 crashpad dump 文件名）\n")
        lines.append("- 被混淆/间接引用\n")
        lines.append("- **大概率不是 Frida 检测，无需担心**\n")
    elif total_xrefs > 0:
        lines.append(f"Friday 有 {total_xrefs} 处 xref，需人工判断是否 Frida 检测逻辑\n")
    
    with open(rp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    
    print(f"[+] {rp}")
    idc.qexit(0)

main()