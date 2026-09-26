"""顺着 sub_46AA74 往上追调用链"""
import sys, os, idc, ida_auto, idautils, ida_funcs, ida_bytes

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(idc.get_input_file_path())
    rp = os.path.join(out, "ssl_callchain.md")
    
    ida_auto.auto_wait()
    
    lines = []
    lines.append("# SSL_write 调用链追踪\n\n")
    
    # 已知: SSL_write 错误日志在 sub_46AA74
    func_ea = 0x46AA74
    func_name = idc.get_func_name(func_ea) or f"sub_{hex(func_ea)}"
    
    lines.append(f"## 起点: {func_name} @ {hex(func_ea)}\n\n")
    
    # 1. 反汇编这个函数
    lines.append(f"### 反汇编 ({func_name})\n\n")
    lines.append("```asm\n")
    
    func = ida_funcs.get_func(func_ea)
    if func:
        start = func.start_ea
        end = func.end_ea
        lines.append(f"; 范围 {hex(start)}-{hex(end)} ({end-start}B)\n\n")
        
        # 找 BL 指令（调用其他函数）
        calls = []
        for ea in idautils.Heads(start, end):
            try:
                disasm = idc.generate_disasm_line(ea, 0)
                if "BL" in disasm or "BLR" in disasm:
                    target = disasm.split()[-1]
                    calls.append((ea, disasm))
                    lines.append(f"  {hex(ea)}: {disasm}  ← ***\n")
                else:
                    lines.append(f"  {hex(ea)}: {disasm}\n")
            except:
                pass
        lines.append("```\n\n")
        
        # 2. 找调用 sub_46AA74 的上层函数
        lines.append(f"### 谁调了 {func_name}\n\n")
        try:
            xrefs = list(idautils.XrefsTo(func_ea))
            lines.append(f"上层调用: {len(xrefs)} 处\n\n")
            lines.append("| 地址 | 所属函数 | 指令 |\n")
            lines.append("| --- | --- | --- |\n")
            for x in xrefs[:20]:
                caller_func = idc.get_func_name(x.frm) or "?"
                try:
                    disasm = idc.generate_disasm_line(x.frm, 0)
                except:
                    disasm = "?"
                lines.append(f"| {hex(x.frm)} | {caller_func} | {disasm} |\n")
        except Exception as e:
            lines.append(f"xref 错误: {e}\n")
    else:
        lines.append(f"函数体未找到（可能 IDA 未识别）\n")
    
    lines.append("\n")
    
    # 3. 在 sub_46AA74 附近搜真实 SSL_write 函数入口
    lines.append("## 附近可能的 OpenSSL 函数\n\n")
    lines.append("在 0x460000-0x470000 范围搜标准函数序言:\n\n")
    
    func_count = 0
    for ea in idautils.Functions():
        if 0x460000 <= ea <= 0x470000:
            name = idc.get_func_name(ea)
            lines.append(f"  {hex(ea)}: {name}\n")
            func_count += 1
    
    lines.append(f"\n该范围共 {func_count} 个函数\n")
    
    with open(rp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    
    print(f"[+] {rp}")
    idc.qexit(0)

main()