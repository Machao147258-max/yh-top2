# -*- coding: utf-8 -*-
"""在 5 个 dex 里搜网易易盾集成痕迹 + 谁声明/调用 Utils.rL。"""
import os,re
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
kws=[b"com/netease/nis/sdkwrapper",b"sdkwrapper",b"showRiskMessage",b"nis/sdkwrapper/Utils",
     b"net/netease",b"yidun",b"YIDUN",b"nis/",b"secsdk",b"libsecsdk",b"AndroidSDK",
     b"muti",b"vmp",b"VMP",b"/Utils",b"rL",b"riskMessage",b"onReceiveRiskMessage"]
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    p=os.path.join(D,fn); d=open(p,"rb").read()
    hits={k:d.count(k) for k in kws if d.count(k)}
    print(f"\n=== {fn} ({len(d)} B) ===")
    for k,c in hits.items(): print(f"   {k.decode()!r}: {c}")
