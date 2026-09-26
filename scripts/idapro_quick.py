"""用 idapro 快速分析 libmxcore.so"""
import sys
from idapro import open_database, close_database

target = r"C:\Users\20751\Desktop\异环\unpacked\so\libmxcore.so"

db = open_database(target, run_auto_analysis=False)  # 不跑全量分析，秒开
if not db:
    print("[×] 打开失败")
    sys.exit(1)

print(f"[*] 架构: {db.arch}")
print(f"[*] 段: {len(db.segments)}")
for name, seg in db.segments.items():
    sz = seg.end_ea - seg.start_ea
    print(f"  {name}: {hex(seg.start_ea)}-{hex(seg.end_ea)} ({sz}B)")

# 搜字符串
keywords = ["Friday", "SSL_write", "SSL_read", "Perfect", "pwrd", "27043", 
            "CA Root", "Certificate", "private key", "sm4-cfb", "SM4"]
for kw in keywords:
    try:
        addrs = db.find_string(kw)
        if addrs:
            for addr in addrs[:3]:
                print(f"[!] '{kw}' @ {hex(addr)}")
                try:
                    refs = list(db.xrefs_to(addr))
                    print(f"    引用: {len(refs)}")
                    for r in refs[:3]:
                        print(f"      ← {hex(r)}")
                except:
                    pass
    except Exception as e:
        pass  # 忽略查不到的

close_database(db)
print("[+] 完成")