# -*- coding: utf-8 -*-
"""retoc list 两个 chunk, 数资产路径。"""
import subprocess, os
W=r"C:\Users\20751\Desktop\异环"
RETOC=os.path.join(W,"tools","retoc.exe")
IO=os.path.join(W,"unpacked","io")
KEY="<REDACTED_AES_KEY>"
for ch in ("pakchunk0-Android_ASTC","pakchunk1-Android_ASTC"):
    utoc=os.path.join(IO,ch+".utoc")
    r=subprocess.run([RETOC,"-a",KEY,"list",utoc],capture_output=True,timeout=300)
    lines=[l for l in r.stdout.decode('utf-8','replace').splitlines() if l.strip()]
    print(f"=== {ch}: rc={r.returncode} 行数={len(lines)}")
    for l in lines[:8]: print("   ",l)
    if r.stderr: print("   ERR",r.stderr.decode('utf-8','replace')[:300])
