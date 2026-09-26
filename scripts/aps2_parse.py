# -*- coding: utf-8 -*-
"""解析 APS2 (DT_ANDROID_RELA), 校验 reloc 数。"""
import struct, collections
SO=r"D:\qwork\libUnreal.so"
raw=open(SO,"rb").read()
start=raw.find(b"APS2"); print("APS2 @", hex(start))
blob=raw[start:start+21048]

def uleb(d,p):
    r=0;s=0
    while True:
        b=d[p];p+=1;r|=(b&0x7f)<<s;s+=7
        if not(b&0x80):break
    return r,p
def sleb(d,p):
    r=0;s=0
    while True:
        b=d[p];p+=1;r|=(b&0x7f)<<s;s+=7
        if not(b&0x80):
            if b&0x40:r|=-(1<<s)
            break
    return r,p

p=4
count,p=uleb(blob,p)
print("声明 reloc 数 =", count)
off=0; rels=[]
while p < len(blob):
    gs,p=uleb(blob,p)
    if gs==0: break
    gd,p=sleb(blob,p)
    off+=gd
    gi,p=uleb(blob,p)
    for k in range(gs):
        ad,p=sleb(blob,p)
        rels.append((off, gi, ad)); off+=8
print("解析 reloc 数 =", len(rels))
tys=collections.Counter((gi&0xffffffff) for _,gi,_ in rels)
print("类型(r_info 低位/type):", dict(tys))
print("示例:", [(hex(o),hex(gi),a) for o,gi,a in rels[:6]])
