"""idapro 快速分析 — 跑所有关键 SO"""
import sys, json, os
from idapro import open_database, close_database

SO_DIR = r"C:\Users\20751\Desktop\异环\unpacked\so"
REPORT = r"C:\Users\20751\Desktop\异环\reports"

targets = ["libkycgm.so", "libmxcore_javasupport.so"]
results = {}

for name in targets:
    path = os.path.join(SO_DIR, name)
    print(f"\n[{name}]")
    
    db = open_database(path, True)
    if not db:
        print(f"  ❌ 打开失败")
        continue
    
    info = {
        "arch": db.arch,
        "segments": {},
        "strings_found": {}
    }
    
    for sname, seg in db.segments.items():
        info["segments"][sname] = {
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea
        }
    
    # 搜关键字符串
    for kw in ["JNI_OnLoad", "SSL_write", "SSL_read", "Friday", "27043",
               "ptrace", "Perfect", "pwrd", "RegisterNatives"]:
        try:
            addrs = db.find_string(kw)
            if addrs:
                refs_info = []
                for addr in addrs[:3]:
                    r = {"addr": hex(addr)}
                    try:
                        refs = list(db.xrefs_to(addr))
                        r["xrefs"] = len(refs)
                        r["xrefs_first"] = [hex(x) for x in refs[:3]]
                    except:
                        r["xrefs"] = "?"
                    refs_info.append(r)
                info["strings_found"][kw] = refs_info
                print(f"  ✓ {kw}: {[x['addr'] for x in refs_info]}")
        except Exception as e:
            pass
    
    results[name] = info
    close_database(db)
    print(f"  ✅ {name} done")

# 写报告
rp = os.path.join(REPORT, "13_idapro_scan.md")
with open(rp, "w", encoding="utf-8") as f:
    f.write("# idapro 快速扫描\n\n")
    for name, info in results.items():
        f.write(f"## {name}\n\n")
        f.write(f"- 架构: {info['arch']}\n")
        f.write("- 段:\n")
        for sname, seg in info['segments'].items():
            f.write(f"  - {sname}: {seg['start']}-{seg['end']} ({seg['size']}B)\n")
        if info['strings_found']:
            f.write("- 关键字符串:\n")
            for kw, addrs in info['strings_found'].items():
                f.write(f"  - {kw}: {addrs}\n")
        f.write("\n")

print(f"\n报告: {rp}")