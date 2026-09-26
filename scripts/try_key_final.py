# -*- coding: utf-8 -*-
"""用 retoc 验证从 0xcdbc40 读出的 key 候选。"""
import subprocess, os
W=r"C:\Users\20751\Desktop\异环"
RETOC=os.path.join(W,"tools","retoc.exe")
# 找 utoc
cands=[]
for root,_,fs in os.walk(os.path.join(W,"unpacked")):
    for f in fs:
        if f.endswith(".utoc"): cands.append(os.path.join(root,f))
print("utoc:", cands)
UTOC=os.path.join(W,"unpacked","io","pakchunk0-Android_ASTC.utoc")
print("使用加密 utoc:", UTOC)
if not UTOC:
    print("无 utoc"); raise SystemExit
keys={
 "32B": "<REDACTED_AES_KEY>",
 "16B": "<REDACTED>",
}
for nm,k in keys.items():
    r=subprocess.run([RETOC,"-a",k,"info",UTOC],capture_output=True,timeout=60)
    print(f"\n=== retoc -a {nm} ({k}) ===")
    print("rc",r.returncode)
    print("out:",r.stdout.decode('utf-8','replace')[:600])
    print("err:",r.stderr.decode('utf-8','replace')[:600])
