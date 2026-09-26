# -*- coding: utf-8 -*-
"""统计解包产出 + 样本文件。"""
import os
W=r"C:\Users\20751\Desktop\异环"
OUT=os.path.join(W,"unpacked","assets")
nf=0; tot=0; exts={}
samples=[]
for root,_,files in os.walk(OUT):
    for f in files:
        p=os.path.join(root,f); nf+=1
        try: sz=os.path.getsize(p)
        except: sz=0
        tot+=sz
        e=os.path.splitext(f)[1].lower() or "(none)"
        exts[e]=exts.get(e,0)+1
        if len(samples)<12: samples.append(os.path.relpath(p,OUT))
print(f"总文件 {nf}  总大小 {tot/1024/1024:.1f} MB")
print("\n扩展名 top20:")
for e,c in sorted(exts.items(),key=lambda x:-x[1])[:20]: print(f"  {c:>6} {e}")
print("\n样本:")
for s in samples: print("  ",s)
