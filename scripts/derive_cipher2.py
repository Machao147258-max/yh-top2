# -*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
so=open(r'D:\qwork\libsecsdk.so','rb').read()
seg=open(r'C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin','rb').read()
V,O,SZ=0x609f0,0x509f0,0x4338
def printable(x): return 0x20<=x<0x7f
# 找 seg 里的可读串段(>=4)
runs=[]; i=0
while i<SZ:
    if printable(seg[V+i]):
        j=i
        while j<SZ and printable(seg[V+j]): j+=1
        if j-i>=4: runs.append((i,j))
        i=j
    else: i+=1
print('可读串段数=%d 总字符=%d'%(len(runs),sum(b-a for a,b in runs)))
fwd={}; conf=0; tot=0
for a,b in runs:
    for k in range(a,b):
        c=so[O+k]; p=seg[V+k]; tot+=1
        if c in fwd and fwd[c]!=p: conf+=1
        fwd.setdefault(c,p)
print('串字符对=%d 冲突=%d'%(tot,conf))
ks=sorted(set(c^p for c,p in fwd.items()))
print('distinct ct^pt=%d'%len(ks), [hex(x) for x in ks[:30]])
for c in sorted(fwd)[:50]:
    print('  0x%02x->0x%02x %r'%(c,fwd[c],chr(fwd[c])))
