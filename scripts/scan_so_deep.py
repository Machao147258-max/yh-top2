"""异环 SO 深度扫描 — 熵分析 + .init_array + 可疑块 + libUnreal.so"""
import os, re, struct, base64, zlib
from pathlib import Path
from collections import Counter

SO_DIR = Path(r"C:\Users\20751\Desktop\异环\unpacked\so")
REPORT_DIR = Path(r"C:\Users\20751\Desktop\异环\reports")

TARGETS = [
    "libkycgm.so",
    "libmxcore_javasupport.so",
    "libmxcore.so",
    "libsecsdk.so",
    "libthemis.so",
    "libclient.so",
    "libUnreal.so",       # ← 这次加上
]

def find_strings(data, min_len=4):
    result = []
    current = b""
    for b in data:
        if 0x20 <= b < 0x7f:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                result.append(current.decode('ascii', errors='replace'))
            current = b""
    if len(current) >= min_len:
        result.append(current.decode('ascii', errors='replace'))
    return result

import math

def entropy(block):
    """计算字节块的香农熵"""
    if not block:
        return 0
    c = Counter(block)
    total = len(block)
    return -sum((freq/total) * math.log2(freq/total) for freq in c.values())

def section_entropy(data):
    """按 4KB 块计算熵，找出高熵区（疑似加密/压缩）"""
    results = []
    block_size = 4096
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) < 16:
            continue
        e = entropy(block)
        if e > 6.0:  # 高熵阈值
            pct = i / len(data) * 100
            results.append((hex(i), len(block), round(e, 2), f"{pct:.0f}%"))
    return results

def scan_init_array(data):
    """找 .init_array 段和 JNI_OnLoad 引用"""
    strs = find_strings(data, 4)
    init_related = [s for s in strs if 'init' in s.lower() or 'INIT' in s]
    jni_refs = [s for s in strs if 'JNI' in s or 'jni' in s.lower()]
    
    # 用 ELF 节头偏移找 .init_array
    # 简单方法：搜特征字节模式 init_array 数组
    results = {
        "init_related_strings": init_related[:20],
        "jni_strings": jni_refs[:10],
    }
    return results

def decode_suspicious(data):
    """找并解码可疑 base64 块"""
    strs = find_strings(data, 24)
    decoded = []
    for s in strs:
        # 纯 base64（长串）
        if re.match(r'^[A-Za-z0-9+/=]{40,}$', s):
            try:
                d = base64.b64decode(s)
                decoded.append({
                    "type": "base64",
                    "raw": s[:60],
                    "raw_len": len(s),
                    "decoded_len": len(d),
                    "decoded_preview": d[:80].decode('latin-1', errors='replace')
                })
            except:
                pass
        # hex 串
        if re.match(r'^[0-9A-Fa-f]{40,}$', s):
            decoded.append({
                "type": "hex",
                "raw": s[:60],
                "raw_len": len(s),
            })
    return decoded

def scan_frida_strings(data):
    """专门扫 Frida 检测相关字符串"""
    strs = find_strings(data, 3)
    patterns = {
        "frida_direct": r'(?i)(frida|gadget|frida-server|frida-agent|frida-gadget|linjector)',
        "frida_port": r'(?i)(27042|27043|31337)',
        "maps_scan": r'(?i)(maps|proc/self|proc/\d+/maps)',
        "ptrace_direct": r'(?i)(ptrace|PTRACE_TRACEME|PTRACE_ATTACH|PTRACE)',
        "thread_check": r'(?i)(pthread_setname_np|thread.*name|getname)',
        "debug_check": r'(?i)(isDebuggerConnected|android:debuggable|ro.debuggable)',
        "tracer_check": r'(?i)(TracerPid|tracer|status.*Tracer)',
        "anti_common": r'(?i)(anti|detect|check.*env|rootbeer|su\.exe)',
        "frida_libs": r'(?i)(libfrida|frida\.|frida_agent|gadget\.so)',
    }
    hits = {}
    for cat, pat in patterns.items():
        matches = set()
        for s in strs:
            if re.search(pat, s):
                matches.add(s[:120])
        if matches:
            hits[cat] = list(matches)[:10]
    return hits

def scan_frida_false_positive_check(data):
    """检查 'Friday' 等疑似误报的上下文"""
    strs = find_strings(data, 4)
    friday_context = [s for s in strs if 'friday' in s.lower() or 'Friday' in s]
    return friday_context[:10]

# ──── 主扫描 ────
all_results = {}

for name in TARGETS:
    path = SO_DIR / name
    if not path.exists():
        all_results[name] = {"status": "NOT_FOUND"}
        print(f"[×] {name}: 不存在")
        continue
    
    size_kb = path.stat().st_size / 1024
    size_mb = size_kb / 1024
    print(f"\n[{name}] ({size_kb:.0f} KB | {size_mb:.1f} MB)")
    
    data = open(path, "rb").read()
    entry = {}
    
    # 1. 熵分析
    print("  [1] 熵分析...")
    high_entropy = section_entropy(data)
    entry["high_entropy_sections"] = high_entropy
    if high_entropy:
        print(f"    高熵块: {len(high_entropy)} 个")
        for off, sz, e, pct in high_entropy[:5]:
            print(f"      {off} ({pct}): 熵={e}, {sz}B")
    else:
        print(f"    无高熵块（整体熵正常，无加密/压缩段）")
    
    # 2. init_array + JNI 引用
    print("  [2] 结构扫描...")
    init_info = scan_init_array(data)
    entry["init_info"] = init_info
    print(f"    init 相关字符串: {len(init_info['init_related_strings'])} 个")
    print(f"    JNI 引用: {len(init_info['jni_strings'])} 个")
    
    # 3. 可疑编码块
    print("  [3] 可疑编码块...")
    suspicious = decode_suspicious(data)
    entry["suspicious_encoded"] = suspicious
    if suspicious:
        for s in suspicious:
            print(f"    {s['type']}: {s['raw_len']}B → 解码{s.get('decoded_len', 0)}B")
            if 'decoded_preview' in s:
                print(f"      预览: {s['decoded_preview'][:60]}")
    
    # 4. Frida 检测专项
    print("  [4] Frida/检测专项...")
    frida_hits = scan_frida_strings(data)
    entry["frida_detection"] = frida_hits
    for cat, matches in sorted(frida_hits.items()):
        print(f"    {cat}: {len(matches)} 处")
        for m in matches[:3]:
            print(f"      → {m[:80]}")
    
    # 5. 检查 "Friday"
    friday = scan_frida_false_positive_check(data)
    if friday:
        entry["friday_context"] = friday
        print(f"    'Friday' 出现: {len(friday)} 处")
        for f in friday:
            print(f"      → {f[:100]}")
    
    all_results[name] = entry

# ──── 写报告 ────
rp = REPORT_DIR / "12_SO深度扫描.md"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

with open(rp, "w", encoding="utf-8") as f:
    f.write("# SO 深度扫描 — 熵 + init_array + Frida检测\n\n")
    
    for name, entry in all_results.items():
        if "status" in entry:
            f.write(f"---\n## {name}: 不存在\n\n")
            continue
        
        size_kb = os.path.getsize(SO_DIR / name) / 1024
        f.write(f"---\n## {name} ({size_kb:.0f} KB)\n\n")
        
        # 熵
        hes = entry.get("high_entropy_sections", [])
        f.write(f"### 熵分析\n\n")
        if hes:
            f.write(f"发现 {len(hes)} 个高熵块（>6.0，疑似加密/压缩）:\n\n")
            f.write("| 偏移 | 大小 | 熵 | 位置 |\n")
            f.write("| --- | --- | --- | --- |\n")
            for off, sz, e, pct in hes[:15]:
                f.write(f"| {off} | {sz}B | {e} | {pct} |\n")
            f.write("\n")
        else:
            f.write("无高熵块 — 代码段未加密/未加壳\n\n")
        
        # 结构
        init = entry.get("init_info", {})
        f.write(f"### 结构\n\n")
        f.write(f"- init 相关字符串: {len(init.get('init_related_strings', []))} 个\n")
        if init.get('init_related_strings'):
            f.write("```\n")
            for s in init['init_related_strings'][:10]:
                f.write(f"{s}\n")
            f.write("```\n")
        f.write(f"- JNI 引用: {len(init.get('jni_strings', []))} 个\n")
        if init.get('jni_strings'):
            f.write("```\n")
            for s in init['jni_strings'][:10]:
                f.write(f"{s}\n")
            f.write("```\n")
        f.write("\n")
        
        # 可疑编码
        enc = entry.get("suspicious_encoded", [])
        if enc:
            f.write(f"### 可疑编码块\n\n")
            f.write(f"| 类型 | 长度 | 解码长度 | 预览 |\n")
            f.write(f"| --- | --- | --- | --- |\n")
            for s in enc[:10]:
                preview = s.get('decoded_preview', '')[:60] if 'decoded_preview' in s else 'N/A'
                f.write(f"| {s['type']} | {s['raw_len']}B | {s.get('decoded_len', '?')}B | `{preview}` |\n")
            f.write("\n")
        
        # Frida 检测
        frida = entry.get("frida_detection", {})
        f.write(f"### Frida / 反检测扫描\n\n")
        if not frida:
            f.write("无命中 — 该 SO 无显式反-Frida/反调试字符串\n\n")
        else:
            for cat, matches in sorted(frida.items()):
                f.write(f"#### {cat}\n\n")
                f.write("```\n")
                for m in matches[:5]:
                    f.write(f"{m}\n")
                f.write("```\n\n")
        
        # Friday 上下文
        friday = entry.get("friday_context", [])
        if friday:
            f.write(f"### 'Friday' 上下文\n\n")
            f.write("```\n")
            for fw in friday:
                f.write(f"{fw}\n")
            f.write("```\n\n")
    
    # 汇总
    f.write("---\n## 汇总\n\n")
    f.write("| SO | 大小 | 高熵块 | init相关 | 可疑编码 | Frida检测 |\n")
    f.write("| --- | --- | --- | --- | --- | --- |\n")
    for name, entry in all_results.items():
        if "status" in entry:
            continue
        size_kb = os.path.getsize(SO_DIR / name) / 1024
        hes = len(entry.get("high_entropy_sections", []))
        init_n = len(entry.get("init_info", {}).get("init_related_strings", []))
        enc_n = len(entry.get("suspicious_encoded", []))
        fd_n = sum(len(v) for v in entry.get("frida_detection", {}).values())
        f.write(f"| {name} | {size_kb:.0f}KB | {hes} | {init_n} | {enc_n} | {fd_n} |\n")

print(f"\n报告: {rp}")