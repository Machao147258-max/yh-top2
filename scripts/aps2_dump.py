# -*- coding: utf-8 -*-
raw=open(r"D:\qwork\libUnreal.so","rb").read()
off=0xa458
blob=raw[off:off+64]
print("head:", blob.hex())
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
c,p=uleb(blob,p); print(f"count(uleb)={c}, p={p}, byte@0x{p-1}={blob[p-1]:02x}")
# 试着连续读若干 uleb 看结构
q=p
for i in range(10):
    v,q=uleb(blob,q); print(f"  uleb[{i}]={v} @byte {q-1}")
q=p
for i in range(6):
    v,q=sleb(blob,q); print(f"  sleb[{i}]={v}")
