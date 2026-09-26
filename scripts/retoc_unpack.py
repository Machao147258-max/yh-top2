# -*- coding: utf-8 -*-
"""解 pakchunk1 ucas + 用 key 解包两个 chunk。"""
import zipfile, os, shutil, subprocess, time
W=r"C:\Users\20751\Desktop\异环"
OBB=os.path.join(W,"unpacked","obb","main.obb")
IO=os.path.join(W,"unpacked","io")
OUT=os.path.join(W,"unpacked","assets")
RETOC=os.path.join(W,"tools","retoc.exe")
KEY="<REDACTED_AES_KEY>"
os.makedirs(OUT,exist_ok=True)
# pakchunk1 ucas
dst=os.path.join(IO,"pakchunk1-Android_ASTC.ucas")
if not os.path.exists(dst):
    print("解 pakchunk1.ucas ...",flush=True); t=time.time()
    oz=zipfile.ZipFile(OBB)
    with oz.open("HT/Content/Paks/pakchunk1-Android_ASTC.ucas") as s, open(dst,"wb") as d:
        shutil.copyfileobj(s,d,64*1024*1024)
    print("done",os.path.getsize(dst),f"{time.time()-t:.0f}s",flush=True)
for ch in ("pakchunk0-Android_ASTC","pakchunk1-Android_ASTC"):
    utoc=os.path.join(IO,ch+".utoc")
    print(f"\n=== unpack {ch} ===",flush=True); t=time.time()
    r=subprocess.run([RETOC,"-a",KEY,"unpack",utoc,OUT],capture_output=True,timeout=3600)
    print("rc",r.returncode,f"{time.time()-t:.0f}s",flush=True)
    print(r.stdout.decode('utf-8','replace')[-800:],flush=True)
    if r.stderr: print("ERR",r.stderr.decode('utf-8','replace')[-800:],flush=True)
print("\nDONE 输出目录:",OUT)
