# -*- coding: utf-8 -*-
so=open(r'D:\qwork\libsecsdk.so','rb').read()
seg=open(r'C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin','rb').read()
V,O,SZ=0x609f0,0x509f0,0x4338
ks=bytes(so[O+i]^seg[V+i] for i in range(SZ))
# 找周期
best=[]
for p in range(1,257):
    m=sum(1 for i in range(SZ) if ks[i]==ks[i%p])
    best.append((m/SZ,p))
best.sort(reverse=True)
print('周期匹配率 top:', [(round(r,3),p) for r,p in best[:10]])
# 打印 ks 前 64
print('ks[:64]=',ks[:64].hex())
# 看 ks 里非零占比
nz=sum(1 for x in ks if x)
print('nonzero=%d/%d'%(nz,SZ))
