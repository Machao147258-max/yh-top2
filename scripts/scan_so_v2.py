"""异环 SO 纯 Python 扫描 — 不用外部命令"""
import os, re, struct
from pathlib import Path

SO_DIR = Path(r"C:\Users\20751\Desktop\异环\unpacked\so")
REPORT_DIR = Path(r"C:\Users\20751\Desktop\异环\reports")

TARGETS = [
    "libkycgm.so",
    "libmxcore_javasupport.so", 
    "libmxcore.so",
    "libsecsdk.so",
    "libthemis.so",
    "libclient.so",
]

def find_strings(data, min_len=4):
    """提取 ASCII 字符串"""
    result = []
    current = b""
    for b in data:
        if 0x20 <= b < 0x7f:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                result.append(current.decode('ascii'))
            current = b""
    if len(current) >= min_len:
        result.append(current.decode('ascii'))
    return result

def scan_elf_header(data):
    """浅解析 ELF 头判断架构"""
    if len(data) < 64:
        return None
    if data[:4] != b'\x7fELF':
        return None
    
    elf_class = data[4]  # 1=32bit, 2=64bit
    endian = data[5]     # 1=LE, 2=BE
    machine = struct.unpack('<H' if endian == 1 else '>H', data[18:20])[0]
    
    arch_map = {
        0x3E: "x86_64 (AMD64)",
        0x28: "ARM (AArch32)",
        0xB7: "AArch64 (ARM64)",
        0x03: "i386 (x86)",
    }
    
    return {
        "class": "64-bit" if elf_class == 2 else "32-bit",
        "endian": "Little" if endian == 1 else "Big",
        "machine_code": machine,
        "machine": arch_map.get(machine, f"Unknown(0x{machine:x})"),
    }

def scan_jni_symbols(data):
    """找 JNI_OnLoad + RegisterNatives + Java_ 模式"""
    strs = find_strings(data, min_len=6)
    results = {
        "has_JNI_OnLoad": "JNI_OnLoad" in strs,
        "has_RegisterNatives": "RegisterNatives" in strs,
        "java_exports": [s for s in strs if s.startswith("Java_")],
        "interesting_jni": [],
    }
    
    # 找 Java_ 签名相关的字符串
    for s in strs:
        if s.startswith("Java_") or "Java_" in s[:100]:
            results["interesting_jni"].append(s)
    
    return results

def scan_keywords(data):
    """多关键词扫描"""
    strs = find_strings(data, min_len=3)
    patterns = {
        # 密钥
        "key/salt/cipher": [r'(?i)(key|salt|cipher|secret|password|token)'],
        "algo_name": [r'(?i)(aes|sm[234]|rsa|md5|sha[0-9]*|gcm|ecb|cbc|hmac|pbkdf|hkdf|chacha|poly1305)'],
        # SSL/网络
        "ssl_tls": [r'(?i)(ssl|tls|openssl|boringssl|x509|certificate|pinning|pinned)'],
        "network_api": [r'(?i)(socket|connect|send|recv|http|curl|libcurl|websocket)'],
        # 检测
        "detect_ptrace": [r'(?i)(ptrace|traceme|antidebug|anti_debug|gdb)'],
        "detect_frida": [r'(?i)(frida|gadget|substrate|xposed|lsposed|frida_)'],
        "detect_maps": [r'(?i)(maps|status|proc/self)'],
        "detect_debug": [r'(?i)(debug|debugger|isDebugger|checkDebug)'],
        # JNI
        "jni": [r'(?i)(JNI_OnLoad|RegisterNatives|FindClass|GetMethodID|GetStaticMethodID|NewStringUTF|CallStaticVoidMethod)'],
        # assets/文件
        "assets": [r'(?i)(assets|AAsset|AssetManager|open|read|file)'],
        # crypto libs
        "crypto_lib": [r'(?i)(libcrypto|libssl|libmbedtls|libnss|libgmp|libsodium)'],
        # 完整性
        "integrity": [r'(?i)(hash|checksum|integrity|verify|sign|signature|tpinfo)'],
    }
    
    hits = {}
    for category, pats in patterns.items():
        matches = set()
        for p in pats:
            for s in strs:
                if re.search(p, s):
                    matches.add(s[:100])  # truncate
        if matches:
            hits[category] = list(matches)[:15]
    
    return hits

def find_key_material(data):
    """找疑似密钥的 16/32 字节块"""
    strs = find_strings(data, min_len=8)
    suspicious = []
    for s in strs:
        # 纯十六进制串（如 "A1B2C3D4..."）
        if re.match(r'^[0-9A-Fa-f]{32,}$', s):
            suspicious.append(f"hex({len(s)}): {s[:64]}")
        # Base64 串
        if re.match(r'^[A-Za-z0-9+/=]{24,}$', s):
            suspicious.append(f"b64({len(s)}): {s[:64]}")
    return suspicious[:20]

# ──── 主扫描 ────
results = {}

for name in TARGETS:
    path = SO_DIR / name
    if not path.exists():
        print(f"[×] {name}: 不存在")
        continue
    
    size_kb = path.stat().st_size / 1024
    print(f"\n[{name}] ({size_kb:.0f} KB)")
    
    data = open(path, "rb").read()
    entry = {
        "size_kb": size_kb,
        "elf": scan_elf_header(data),
        "jni": scan_jni_symbols(data),
        "keywords": scan_keywords(data),
        "key_material": find_key_material(data),
    }
    
    # 摘要
    elf_info = entry["elf"]
    if elf_info:
        print(f"  ELF: {elf_info['machine']}, {elf_info['class']}, {elf_info['endian']}")
    else:
        print(f"  ELF: 无法解析（非标准 ELF 或分段文件）")
    
    jni = entry["jni"]
    print(f"  JNI_OnLoad: {jni['has_JNI_OnLoad']}, RegisterNatives: {jni['has_RegisterNatives']}")
    print(f"  Java_ 导出: {len(jni['java_exports'])} 个")
    
    kw = entry["keywords"]
    print(f"  keywords hits: {sum(len(v) for v in kw.values())}")
    for cat, matches in sorted(kw.items()):
        print(f"    {cat}: {len(matches)}")
    
    results[name] = entry

# ──── 写入报告 ────
REPORT_DIR.mkdir(parents=True, exist_ok=True)
rp = REPORT_DIR / "11_SO静态扫描结果.md"

with open(rp, "w", encoding="utf-8") as f:
    f.write("# SO 静态扫描结果\n\n")
    f.write("> 纯 Python 扫描（不用外部命令）\n\n")
    
    for name, entry in results.items():
        f.write(f"---\n")
        f.write(f"## {name} ({entry['size_kb']:.0f} KB)\n\n")
        
        # ELF
        elf = entry["elf"]
        if elf:
            f.write(f"### ELF 信息\n\n")
            f.write(f"- 架构: {elf['machine']}\n")
            f.write(f"- {elf['class']}, {elf['endian']} endian\n\n")
        else:
            f.write(f"⚠ 非标准 ELF 或无法解析\n\n")
        
        # JNI
        jni = entry["jni"]
        f.write(f"### JNI 接口\n\n")
        f.write(f"- JNI_OnLoad: {'✅' if jni['has_JNI_OnLoad'] else '❌'}\n")
        f.write(f"- RegisterNatives: {'✅' if jni['has_RegisterNatives'] else '❌'}\n")
        f.write(f"- Java_ 导出符号: {len(jni['java_exports'])} 个\n\n")
        if jni['java_exports']:
            f.write("```\n")
            for e in jni['java_exports'][:30]:
                f.write(f"{e}\n")
            f.write("```\n\n")
        
        # Keywords
        kw = entry["keywords"]
        f.write(f"### 关键词扫描\n\n")
        if not kw:
            f.write("无命中\n\n")
        else:
            for cat, matches in sorted(kw.items()):
                f.write(f"#### {cat} ({len(matches)} 处)\n\n")
                f.write("```\n")
                for m in matches:
                    f.write(f"{m}\n")
                f.write("```\n\n")
        
        # Key material
        km = entry["key_material"]
        if km:
            f.write(f"### 疑似密钥材料\n\n")
            f.write("```\n")
            for k in km:
                f.write(f"{k}\n")
            f.write("```\n\n")
    
    # 汇总对比表
    f.write(f"---\n")
    f.write(f"## 汇总对比\n\n")
    f.write(f"| SO | 大小 | 架构 | JNI_OnLoad | RegisterNatives | Java_导出 | 关键词命中 |\n")
    f.write(f"| --- | --- | --- | --- | --- | --- | --- |\n")
    for name, entry in results.items():
        elf = entry["elf"]
        arch = elf["machine"] if elf else "?"
        jni = entry["jni"]
        jol = "✅" if jni["has_JNI_OnLoad"] else "❌"
        rn = "✅" if jni["has_RegisterNatives"] else "❌"
        je = len(jni["java_exports"])
        kw_total = sum(len(v) for v in entry["keywords"].values())
        f.write(f"| {name} | {entry['size_kb']:.0f}KB | {arch} | {jol} | {rn} | {je} | {kw_total} |\n")

print(f"\n报告: {rp}")