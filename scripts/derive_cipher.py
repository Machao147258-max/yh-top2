# -*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
so=open(r'D:\qwork\libsecsdk.so','rb').read()
seg=open(r'C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin','rb').read()
V,O,SZ=0x609f0,0x509f0,0x4338
fwd={}; conflict=0; pairs=0
for i in range(SZ):
    c=so[O+i]; p=seg[V+i]
    if c==p: continue
    pairs+=1
    if c in fwd and fwd[c]!=p: conflict+=1
    fwd.setdefault(c,p)
print('diff pairs=%d  same-ct-diff-pt conflicts=%d'%(pairs,conflict))
vis={}; conf2=0; n2=0
for i in range(SZ):
    c=so[O+i]; p=seg[V+i]
    if c==p: continue
    if 0x20<=p<0x7f:
        n2+=1
        if c in vis and vis[c]!=p: conf2+=1
        vis.setdefault(c,p)
print('ascii pairs=%d conflicts=%d'%(n2,conf2))
for c in sorted(vis)[:40]:
    print('  0x%02x -> 0x%02x %r'%(c,vis[c],chr(vis[c])))
ks=set(c^p for c,p in vis.items())
print('distinct ct^pt =',len(ks), sorted(ks)[:20])
