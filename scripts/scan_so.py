"""异环 SO 批量分析 — 静态扫描版
目标：验证之前推断，找出密钥来源 / 检测逻辑 / JNI 接口 / 网络层
方法：lief + strings + capstone
"""
import lief
import subprocess, json, sys, os, re
from pathlib import Path

SO_DIR = Path(r"C:\Users\20751\Desktop\异环\unpacked\so")
REPORT_DIR = Path(r"C:\Users\20751\Desktop\异环\reports")

TARGETS = [
    "libkycgm.so",              # 157KB, 国密
    "libmxcore_javasupport.so", # 362KB, IM JNI
    "libsecsdk.so",             # ? 安全SDK
    "libthemis.so",             # ? 可能是安全库
    "libclient.so",             # ? 客户端
]

def run_strings(path, patterns):
    """strings + grep 找特定模式"""
    try:
        result = subprocess.run(
            ["strings", "-a", str(path)],
            capture_output=True, text=True, timeout=30
        )
        lines = result.stdout.splitlines()
        hits = {}
        for p in patterns:
            matches = [l for l in lines if re.search(p, l, re.IGNORECASE)]
            if matches:
                hits[p] = matches[:20]  # cap 20 per pattern
        return hits
    except Exception as e:
        return {"_error": str(e)}

def analyze_elf(path):
    """用 lief 解析 ELF 结构"""
    try:
        binary = lief.parse(str(path))
        if binary is None:
            return {"error": "lief failed to parse"}
        
        info = {
            "arch": str(binary.header.machine_type),
            "bits": binary.header.identity_class,
            "entry": hex(binary.header.entrypoint),
            "sections": [],
            "exports_raw": [],
            "exports_java": [],
        }
        
        for s in binary.sections:
            info["sections"].append({
                "name": s.name,
                "vaddr": hex(s.virtual_address),
                "size": s.size,
                "flags": str(s.flags)
            })
        
        # 导出符号
        if hasattr(binary, 'exported_functions'):
            for f in binary.exported_functions:
                name = f.name
                addr = hex(f.address)
                info["exports_raw"].append(f"{addr}: {name}")
                if "Java_" in name:
                    info["exports_java"].append(f"{addr}: {name}")
        
        return info
    except Exception as e:
        return {"error": str(e)}

def search_key_bytes(path):
    """搜疑似密钥的字节数组 (16/32字节连续高熵)"""
    try:
        data = open(path, "rb").read()
        # 找连续的 16 或 32 字节，不包含可打印字符的"看起来像密钥"的区域
        # 简单策略：找 .rodata 段里的 16/32 字节非零序列
        results = []
        # 用 strings 的 -n 16 找长串
        result = subprocess.run(
            ["strings", "-n", "16", str(path)],
            capture_output=True, text=True, timeout=30
        )
        long_strings = [l for l in result.stdout.splitlines() 
                       if len(l) >= 16 and not any(c.isprintable() for c in l[:16])]
        return long_strings[:30]
    except:
        return []

# ──── 主扫描 ────
results = {}

for name in TARGETS:
    path = SO_DIR / name
    if not path.exists():
        results[name] = {"status": "NOT_FOUND"}
        continue
    
    print(f"\n{'='*60}")
    print(f"扫描: {name} ({path.stat().st_size / 1024:.0f} KB)")
    print('='*60)
    
    entry = {"size_kb": path.stat().st_size / 1024}
    
    # 1. ELF 结构
    print("[1] ELF 结构...")
    elf = analyze_elf(path)
    entry["elf"] = elf
    
    # 2. 字符串扫描 (密钥/SSL/检测)
    print("[2] 关键词扫描...")
    strs = run_strings(path, [
        "key", "salt", "cipher", "aes", "sm[234]", "gcm", "rsa", "md5", "sha",
        "ssl", "tls", "x509", "certificate", "pinning",
        "ptrace", "frida", "gadget", "substrate", "maps", "debug",
        "socket", "connect", "send", "recv", "http", "curl",
        "assets", "getDeviceId", "getAndroidId",
        "JNI_OnLoad", "RegisterNatives",
        "pkcs", "private.key", "BEGIN ",
    ])
    entry["strings"] = {k: v for k, v in strs.items() if k != "_error"}
    if "_error" in strs:
        entry["strings_error"] = strs["_error"]
    
    # 3. 导出符号汇总
    if "exports_java" in elf:
        print(f"  JNI 导出: {len(elf['exports_java'])} 个")
    if "exports_raw" in elf:
        print(f"  总导出: {len(elf['exports_raw'])} 个")
    
    # 4. 密钥字节搜索
    print("[3] 密钥字节搜索...")
    keys = search_key_bytes(path)
    if keys:
        entry["suspicious_bytes"] = keys[:10]
    
    results[name] = entry

# ──── 输出报告 ────
REPORT_DIR.mkdir(parents=True, exist_ok=True)
report_path = REPORT_DIR / "11_SO静态扫描结果.md"

with open(report_path, "w", encoding="utf-8") as f:
    f.write("# SO 静态扫描结果\n\n")
    f.write(f"> 扫描时间: \n")
    f.write(f"> 工具: lief + strings + capstone\n\n")
    
    for name, data in results.items():
        f.write(f"---\n\n")
        f.write(f"## {name} ({data.get('size_kb', 0):.0f} KB)\n\n")
        
        if "error" in data:
            f.write(f"错误: {data['error']}\n\n")
            continue
        
        # ELF 信息
        elf = data.get("elf", {})
        if "error" not in elf:
            f.write(f"### ELF 结构\n\n")
            f.write(f"- 架构: {elf.get('arch')} | {elf.get('bits')}\n")
            f.write(f"- Entry: {elf.get('entry')}\n")
            f.write(f"- 导出函数总数: {len(elf.get('exports_raw', []))}\n")
            f.write(f"- JNI 导出: {len(elf.get('exports_java', []))}\n\n")
            
            f.write(f"#### JNI 导出清单\n\n")
            f.write("```\n")
            for e in elf.get("exports_java", []):
                f.write(f"{e}\n")
            f.write("```\n\n")
            
            f.write(f"#### 节表\n\n")
            f.write("| 节名 | vaddr | 大小 | 权限 |\n")
            f.write("| --- | --- | --- | --- |\n")
            for s in elf.get("sections", []):
                f.write(f"| {s['name']} | {s['vaddr']} | {s['size']} | {s['flags']} |\n")
            f.write("\n")
        
        # 字符串命中
        strs = data.get("strings", {})
        if strs:
            f.write(f"### 关键词命中\n\n")
            for pat, matches in sorted(strs.items()):
                f.write(f"- **{pat}**: {len(matches)} 处\n")
                for m in matches[:5]:
                    f.write(f"  - `{m[:120]}`\n")
                if len(matches) > 5:
                    f.write(f"  - ... 还有 {len(matches)-5} 处\n")
                f.write("\n")
        else:
            f.write(f"### 关键词命中\n\n无\n\n")
        
        # 可疑字节
        keys = data.get("suspicious_bytes", [])
        if keys:
            f.write(f"### 可疑密钥字节\n\n")
            f.write("```\n")
            for k in keys[:5]:
                f.write(f"{k[:64]}\n")
            f.write("```\n\n")

# 终端摘要
print(f"\n报告已写入: {report_path}")
for name, data in results.items():
    elf = data.get("elf", {})
    jni_count = len(elf.get("exports_java", [])) if "error" not in elf else 0
    str_count = sum(len(v) for v in data.get("strings", {}).values())
    print(f"  {name:35s} JNI={jni_count:3d}  strings_hits={str_count:3d}")