"""从 sub_46DF94 往上追 SSL_write 调用链 — 找函数体"""
import sys, os, idc, ida_auto, idautils, ida_funcs

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(idc.get_input_file_path())
    rp = os.path.join(out, "ssl_deep.md")
    
    ida_auto.auto_wait()
    
    lines = []
    lines.append("# SSL 深层调用链追查\n\n")
    
    # 已知: sub_46DF94 调了 sub_46AA74 (SSL_write 错误处理)
    # 追 sub_46DF94 看它怎么调 SSL_write
    func_ea = 0x46DF94
    
    lines.append(f"## sub_46DF94 @ {hex(func_ea)}\n\n")
    
    func = ida_funcs.get_func(func_ea)
    if not func:
        lines.append("函数未找到\n")
        with open(rp, "w") as f: f.writelines(lines)
        print(f"[+] {rp}")
        idc.qexit(0)
        return
    
    start, end = func.start_ea, func.end_ea
    lines.append(f"范围: {hex(start)}-{hex(end)} ({end-start}B)\n\n")
    
    # 反汇编 + 收集所有 BL 调用
    bl_targets = []
    lines.append("### 所有 BL 调用\n\n")
    lines.append("| 地址 | 指令 | 目标 | 目标函数名 |\n")
    lines.append("| --- | --- | --- | --- |\n")
    
    for ea in idautils.Heads(start, end):
        try:
            disasm = idc.generate_disasm_line(ea, 0)
            if "BL" in disasm and "B.L" not in disasm:
                parts = disasm.split()
                target = parts[-1] if len(parts) > 1 else "?"
                # 尝试转地址
                try:
                    t_addr = int(target.replace("sub_", "0x"), 16) if "sub_" in target else 0
                    if not t_addr:
                        t_addr = int(target, 16) if target.startswith("0x") else 0
                except:
                    t_addr = 0
                
                t_name = idc.get_func_name(t_addr) if t_addr else "?"
                bl_targets.append((ea, disasm, target, t_name))
                lines.append(f"| {hex(ea)} | {disasm} | {target} | {t_name} |\n")
        except:
            pass
    
    # 对每个 BL 目标，看有没有 SSL 特征
    lines.append("\n### BL 目标中的 SSL 相关函数\n\n")
    ssl_keywords = ["SSL", "ssl", "bio", "BIO", "tls", "TLS", "x509", "X509", 
                    "cert", "CERT", "pem", "PEM", "handshake", "connect", "CTX"]
    
    found_any = False
    for ea, disasm, target, t_name in bl_targets:
        t_addr = bl_targets[0][0]  # just placeholder
        try:
            t_addr_val = int(target.replace("sub_", "0x"), 16) if "sub_" in target else 0
            if not t_addr_val:
                t_addr_val = int(target, 16) if target.startswith("0x") else 0
            # 看目标函数内部有没有 SSL 相关字符串
            t_func = ida_funcs.get_func(t_addr_val)
            if t_func:
                for s_ea in idautils.Heads(t_func.start_ea, t_func.end_ea):
                    try:
                        s_content = idc.get_strlit_contents(s_ea)
                        if s_content:
                            for kw in ssl_keywords:
                                if kw.encode() in s_content:
                                    found_any = True
                                    lines.append(f"- {target} ({t_name}) 包含 '{kw}' 字符串\n")
                                    break
                    except:
                        pass
        except:
            pass
    
    if not found_any:
        lines.append("（BL 目标中无明显 SSL 字符串特征，SSL 函数可能在更上层）\n")
    
    # 看谁调了 sub_46DF94
    lines.append("\n## sub_46DF94 的上层调用\n\n")
    try:
        callers = list(idautils.XrefsTo(func_ea))
        lines.append(f"共 {len(callers)} 处调用\n\n")
        lines.append("| 地址 | 所属函数 |\n")
        lines.append("| --- | --- |\n")
        for c in callers[:10]:
            c_func = idc.get_func_name(c.frm) or "?"
            lines.append(f"| {hex(c.frm)} | {c_func} |\n")
    except Exception as e:
        lines.append(f"xref 错误: {e}\n")
    
    with open(rp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    
    print(f"[+] {rp}")
    idc.qexit(0)

main()