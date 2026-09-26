# -*- coding: utf-8 -*-
"""用 retoc 试各种候选 key, 找能解析的。"""
import subprocess, os, re
W=r"C:\Users\20751\Desktop\异环"
RETOC=os.path.join(W,"tools","retoc.exe")
UTOC=os.path.join(W,"unpacked","io","pakchunk0-Android_ASTC.utoc")
SO=os.path.join(W,"unpacked","so","libUnreal.so")
cands={}
G16="4f6f646c650000000000000000000000"
cands["Oodle16"]=G16
cands["Oodle32"]=G16+"0"*32
cands["Oodle_pad32"]="4f6f646c65"+"00"*27
cands["zero32"]="00"*32
cands["Oodle_xor"]=G16+G16
# 44 个 so 里的 hex 串
raw=open(SO,"rb").read()
strs=re.findall(rb"[\x20-\x7e]{6,200}", raw)
hexre=re.compile(rb"^[0-9a-fA-F]{32}$")
for s in set(x for x in strs if hexre.match(x)):
    cands["so_"+s.decode()[:12]]=s.decode()+"0"*32   # 16B -> 32B(右补零)
for name,k in list(cands.items())[:0]:
    pass
print(f"候选 {len(cands)} 个")
ok=[]
for name,k in cands.items():
    try:
        r=subprocess.run([RETOC,"-a",k,"info",UTOC], capture_output=True, timeout=30)
        out=(r.stdout+r.stderr).decode(errors="replace")
        if r.returncode==0:
            print(f"*** {name} (key={k}) 成功! ***")
            print(out[:400]); ok.append(name)
    except Exception as e:
        pass
print("成功:", ok if ok else "无")
