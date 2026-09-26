# -*- coding: utf-8 -*-
"""试游戏相关字符串派生的 AES key (retoc 验证)。"""
import subprocess, os, hashlib
W=r"C:\Users\20751\Desktop\异环"
RETOC=os.path.join(W,"tools","retoc.exe")
UTOC=os.path.join(W,"unpacked","io","pakchunk0-Android_ASTC.utoc")
bases=[b"com.hottagames.yh.laohu", b"hottagames", b"laohu", b"NTE", b"NevernessToEverness",
       b"yh", b"Hottha", b"Hotta", b"Oodle", b"hottagames.yh", b"yh.laohu", b"pwrd", b"onesdk",
       b"1289", b"HT", b"OodleLZ", b"Kraken", b"htgame", b"Anomaly"]
cands={}
for b in bases:
    cands[b.decode()+":md5"]=hashlib.md5(b).hexdigest()
    cands[b.decode()+":sha1"]=hashlib.sha1(b).hexdigest()          # 40 hex=20B
    cands[b.decode()+":sha256"]=hashlib.sha256(b).hexdigest()
    cands[b.decode()+":raw32"]=(b+b"\x00"*32)[:32].hex()
    cands[b.decode()+":dup32"]=(b*8)[:32].hex()
print(f"候选 {len(cands)}")
ok=[]
for name,k in cands.items():
    if len(k) not in (32,48,64): 
        # retoc 只接受 16/24/32 字节
        continue
    try:
        r=subprocess.run([RETOC,"-a",k,"info",UTOC],capture_output=True,timeout=20)
        if r.returncode==0:
            print(f"*** 成功 {name} = {k} ***"); ok.append(name)
    except Exception: pass
print("成功:", ok if ok else "无")
