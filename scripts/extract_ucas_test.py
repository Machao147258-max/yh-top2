# -*- coding: utf-8 -*-
"""从 OBB 解 pakchunk0 的 ucas 到 io 目录, 再用 key 跑 retoc info。"""
import zipfile, os, shutil, subprocess
W=r"C:\Users\20751\Desktop\异环"
OBB=os.path.join(W,"unpacked","obb","main.obb")
IO=os.path.join(W,"unpacked","io")
RETOC=os.path.join(W,"tools","retoc.exe")
KEY="<REDACTED_AES_KEY>"
# 解 ucas
for fn in ["pakchunk0-Android_ASTC.ucas"]:
    dst=os.path.join(IO,fn)
    if not os.path.exists(dst) or os.path.getsize(dst)==0:
        print("解",fn,flush=True)
        oz=zipfile.ZipFile(OBB)
        with oz.open("HT/Content/Paks/"+fn) as s, open(dst,"wb") as d:
            shutil.copyfileobj(s,d,64*1024*1024)
        print("done",os.path.getsize(dst),flush=True)
    else: print(fn,"已存在",os.path.getsize(dst))
utoc=os.path.join(IO,"pakchunk0-Android_ASTC.utoc")
print("\n=== retoc -a KEY info",utoc,"===")
r=subprocess.run([RETOC,"-a",KEY,"info",utoc],capture_output=True,timeout=120)
print("rc",r.returncode)
print(r.stdout.decode('utf-8','replace')[:2000])
print("ERR",r.stderr.decode('utf-8','replace')[:800])
