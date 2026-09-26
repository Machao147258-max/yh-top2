"""idat SO 分析脚本 — IDA 9.x 兼容版
用法: idat -A -S"idat_analyze_so.py out_dir" target.so
"""
import sys, os
import idc
import ida_auto
import ida_funcs
import ida_segment
import ida_bytes
import ida_lines
import ida_nalt

def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(idc.get_input_file_path())
    
    base_name = os.path.splitext(os.path.basename(idc.get_input_file_path()))[0]
    report_path = os.path.join(out_dir, f"{base_name}_idat_report.md")
    
    print(f"[*] idat 分析: {idc.get_input_file_path()}")
    print(f"[*] 输出: {report_path}")
    
    ida_auto.auto_wait()
    
    lines = []
    lines.append(f"# {base_name} — idat 静态分析\n")
    lines.append(f"> IDA Pro 9.4 | {idc.get_input_file_path()}\n")
    
    # ── 基本信息 ──
    lines.append("## 基本信息\n")
    
    seg_qty = ida_segment.get_segm_qty()
    func_count = 0
    try:
        ea = idc.cvar.inf.min_ea
        func_count = len(list(ida_funcs.func_tail_iterator_t(ea, idc.cvar.inf.max_ea)))
    except:
        func_count = "?"
    
    lines.append(f"- **段数**: {seg_qty}\n")
    lines.append(f"- **函数数**: {func_count}\n")
    
    # ── 段表 ──
    lines.append("### 段表\n")
    lines.append("| 段名 | 起始 | 大小 | 权限 |\n")
    lines.append("| --- | --- | --- | --- |\n")
    for i in range(seg_qty):
        seg = ida_segment.getnseg(i)
        if seg:
            name = ida_segment.get_segm_name(seg)
            start = seg.start_ea
            end = seg.end_ea
            size = end - start
            perm_str = ""
            if seg.perm & idc.SEGPERM_R: perm_str += "R"
            if seg.perm & idc.SEGPERM_W: perm_str += "W"
            if seg.perm & idc.SEGPERM_X: perm_str += "X"
            lines.append(f"| {name} | {hex(start)} | {size} | {perm_str} |\n")
    
    # ── 导出符号（遍历所有函数） ──
    lines.append("\n## 导出符号\n")
    java_exports = []
    named = []
    
    # IDA 9.x: 用 ida_funcs.get_func 遍历
    # 简单方法：枚举所有命名地址
    for ea in idautils.Names():
        name = idc.get_name(ea)
        if name:
            # 跳过自动生成的
            if name.startswith("sub_") or name.startswith("loc_") or name.startswith("off_") or name.startswith("unk_"):
                continue
            if name.startswith(".") or name.startswith("$"):
                continue
            if "Java_" in name:
                java_exports.append((ea, name))
            else:
                named.append((ea, name))
    
    lines.append(f"### JNI 导出 ({len(java_exports)})\n")
    if java_exports:
        lines.append("```\n")
        for ea, name in java_exports:
            lines.append(f"{hex(ea)}  {name}\n")
        lines.append("```\n")
    else:
        lines.append("无 Java_ 命名符号\n")
    
    lines.append(f"### 其他命名非自动符号 ({len(named)})\n")
    if named:
        lines.append("```\n")
        for ea, name in named[:50]:
            lines.append(f"{hex(ea)}  {name}\n")
        lines.append("```\n")
    
    # ── 关键字符串 ──
    lines.append("\n## 关键字符串\n")
    
    search_terms = [
        "JNI_OnLoad", "RegisterNatives",
        "SSL_CTX", "SSL_write", "SSL_read",
        "sm4", "sm2", "aes", "rsa",
        "ptrace", "frida", "gadget",
        "curl", "connect", "socket",
        "Friday", "27042", "27043",
        "Perfect", "pwrd",
    ]
    
    for term in search_terms:
        ea = idc.get_name_ea_simple(term) if hasattr(idc, 'get_name_ea_simple') else 0xFFFFFFFF
        if ea and ea != 0xFFFFFFFF:
            try:
                xrefs = list(idautils.XrefsTo(ea))
                lines.append(f"- **{term}** @ {hex(ea)} ({len(xrefs)} 处引用)\n")
                for x in xrefs[:5]:
                    caller = idc.get_func_name(x.frm) or "?"
                    if not caller:
                        caller = hex(x.frm)
                    lines.append(f"  ← {hex(x.frm)} ({caller})\n")
                if len(xrefs) > 5:
                    lines.append(f"  ... +{len(xrefs)-5}\n")
            except:
                lines.append(f"- **{term}** @ {hex(ea)}\n")
    
    # ── 字符串列表（关键字匹配） ──
    lines.append("\n## 字符串列表（关键字匹配）\n")
    str_kw = ["key", "salt", "aes", "sm2", "sm4", "rsa", "ssl", "cert",
              "frida", "ptrace", "gadget", "friday", "perfect", "pwrd",
              "private", "secret", "token", "sign", "jni"]
    
    found = []
    for seg_idx in range(seg_qty):
        seg = ida_segment.getnseg(seg_idx)
        if not seg:
            continue
        sname = ida_segment.get_segm_name(seg)
        if sname in (".rodata", ".data", ".rdata", ".got", ".plt", ".dynstr", ".dynsym"):
            ea = seg.start_ea
            end = seg.end_ea
            while ea < end:
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_strlit(flags):
                    s = idc.get_strlit_contents(ea)
                    if s and len(s) < 120:
                        try:
                            s_dec = s.decode('utf-8', errors='replace')
                            for kw in str_kw:
                                if kw.lower() in s_dec.lower():
                                    found.append((hex(ea), s_dec))
                                    break
                        except:
                            pass
                    ea = idc.next_head(ea, end)
                else:
                    ea = idc.next_head(ea, end)
    
    if found:
        for addr, s in sorted(found, key=lambda x: x[0]):
            lines.append(f"- {addr}: `{s}`\n")
    else:
        lines.append("（无命中）\n")
    
    # ── init_array ──
    lines.append("\n## init_array / 启动逻辑\n")
    for seg_idx in range(seg_qty):
        seg = ida_segment.getnseg(seg_idx)
        if not seg: continue
        sname = ida_segment.get_segm_name(seg)
        if "init" in sname.lower():
            sz = ida_segment.get_segm_end(seg) - seg.start_ea
            lines.append(f"- 段: {sname} @ {hex(seg.start_ea)} ({sz}B)\n")
            cnt = 0
            ea = seg.start_ea
            end = ida_segment.get_segm_end(seg)
            while ea < end and cnt < 20:
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_code(flags):
                    try:
                        line = idc.generate_disasm_line(ea, 0)
                        lines.append(f"  {hex(ea)}: {line}\n")
                        cnt += 1
                    except:
                        pass
                ea = idc.next_head(ea, end)
    
    # ── 总结 ──
    lines.append("\n## 总结\n")
    lines.append(f"- 段数: {seg_qty}\n")
    lines.append(f"- JNI 导出: {len(java_exports)}\n")
    lines.append(f"- 关键字符串命中: {len(found)}\n")
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    
    print(f"[+] 报告: {report_path}")
    idc.qexit(0)

if __name__ == "__main__":
    # 手动导入 idautils
    import idautils
    main()