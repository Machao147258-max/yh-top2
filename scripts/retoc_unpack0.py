# -*- coding: utf-8 -*-
"""重跑 pakchunk0 解包 (Oodle DLL 已就位)。"""
import subprocess, os, time
W=r"C:\Users\20751\Desktop\异环"
RETOC=os.path.join(W,"tools","retoc.exe")
IO=os.path.join(W,"unpacked","io")
OUT=os.path.join(W,"unpacked","assets")
KEY="<REDACTED_AES_KEY>"
t=time.time()
r=subprocess.run([RETOC,"-a",KEY,"unpack",os.path.join(IO,"pakchunk0-Android_ASTC.utoc"),OUT],
                 capture_output=True,timeout=3600)
print("rc",r.returncode,f"{time.time()-t:.0f}s")
print(r.stdout.decode('utf-8','replace')[-500:])
if r.stderr: print("ERR",r.stderr.decode('utf-8','replace')[-500:])
