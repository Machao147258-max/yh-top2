"""查 sub_46AA74 的 BL 目标 — 看有没有 SSL 相关"""
import sys, os, idc, ida_auto, idautils, ida_funcs, ida_bytes

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(idc.get_input_file_path())
    rp = os.path.join(out, "ssl_funcs.md")
    
    ida_auto.auto_wait()
    
    # 从 sub_46AA74 周围收集所有 BL 目标
    # 然后在目标函数里搜 SSL 相关字符串
    start, end = 0x460000, 0x470000
    found = []
    
    for ea in idautils.Functions():
        if ea < start or ea > end:
            continue
        f_start = ida_funcs.get_func(ea).start_ea
        f_end = ida_funcs.get_func(ea).end_ea
        name = idc.get_func_name(ea)
        
        # 在这个函数里搜字符串
        for s_ea in idautils.Heads(f_start, f_end):
            try:
                flags = ida_bytes.get_full_flags(s_ea)
                if ida_bytes.is_strlit(flags):
                    s = idc.get_strlit_contents(s_ea)
                    if not s:
                        continue
                    s_decoded = s.decode('utf-8', errors='replace')
                    for kw in ["SSL", "ssl", "BIO", "TLS", "tls", "X509", "x509",
                               "OPENSSL", "OpenSSL", "certificate", "Certificate",
                               "handshake", "connect"]:
                        if kw in s_decoded:
                            found.append((ea, name, hex(s_ea), s_decoded[:80]))
                            break
            except:
                pass
    
    lines = []
    lines.append("# SSL 相关字符串在 0x460000-0x470000 函数中\n\n")
    lines.append(f"找到 {len(found)} 处\n\n")
    
    for func_ea, func_name, str_addr, content in found:
        lines.append(f"- {func_name} @ {hex(func_ea)}: `{content}`\n")
    
    lines.append(f"\n## 候选 SSL 函数\n\n")
    ssl_candidates = set()
    for func_ea, func_name, str_addr, content in found:
        if any(kw in content for kw in ["SSL_CTX", "SSL_new", "SSL_connect", "BIO_new", "SSL_set"]):
            ssl_candidates.add((func_ea, func_name, content))
    
    if ssl_candidates:
        for func_ea, func_name, hint in sorted(ssl_candidates):
            lines.append(f"- **{func_name}** @ {hex(func_ea)}: `{hint}`\n")
    else:
        lines.append("(无直接 SSL 函数名命中，均在 sub_ 中)\n")
    
    with open(rp, "w") as f:
        f.writelines(lines)
    
    print(f"[+] {rp}")
    idc.qexit(0)

main()