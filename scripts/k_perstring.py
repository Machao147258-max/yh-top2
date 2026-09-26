# -*- coding: utf-8 -*-
so=open(r'D:\qwork\libsecsdk.so','rb').read()
seg=open(r'C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin','rb').read()
V,O,SZ=0x609f0,0x509f0,0x4338
runs=[]; i=0
while i<SZ:
    if 0x20<=seg[V+i]<0x7f:
        j=i
        while j<SZ and 0x20<=seg[V+j]<0x7f: j+=1
        if j-i>=6: runs.append((i,j))
        i=j
    else: i+=1
for a,b in runs[:8]:
    s=seg[V+a:V+b].split(b'\x00')[0][:40]
    ks=sorted(set((so[O+k]-seg[V+k])&0xff for k in range(a,b)))
    print('@0x%x  %r'%(V+a, s))
    print('   K(pt-ct) =', [hex(x) for x in ks])
print('总串段', len(runs))
