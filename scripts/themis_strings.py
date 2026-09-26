# -*- coding: utf-8 -*-
"""libthemis 字符串混淆分析: 提取串 + 尝试反转/解码。"""
import re, os
W=r"C:\Users\20751\Desktop\异环"
SO=os.path.join(W,"unpacked","so","libthemis.so")
raw=open(SO,"rb").read()
print(f"libthemis.so {len(raw)}B")
strs=re.findall(rb"[\x20-\x7e]{6,120}", raw)
print(f"可读串 {len(strs)} 条")
# 反转后是否更像正常(含常见关键词)
KW=["/proc/","/data/","/system","su","magisk","frida","xposed","maps","emulator",
    "qemu","/dev/","ptrace","tracerpid","ro.","root","http",".so","http","themis","detect"]
def reverse(s): return s[::-1]
hits_rev=[]; hits_raw=[]
for s in set(strs):
    t=s.decode('latin1')
    r=t[::-1]
    for k in KW:
        if k in t.lower(): hits_raw.append((k,t))
        if k in r.lower(): hits_rev.append((k,t,r))
print(f"\n原串直接命中关键词: {len(hits_raw)}")
for k,t in hits_raw[:30]: print(f"  [{k}] {t!r}")
print(f"\n反转后命中关键词: {len(hits_rev)}")
for k,t,r in hits_rev[:40]: print(f"  [{k}] {t!r}  ->  {r!r}")
