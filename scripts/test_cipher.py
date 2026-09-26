# -*- coding: utf-8 -*-
so=open(r'D:\qwork\libsecsdk.so','rb').read()
seg=open(r'C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin','rb').read()
V,O,SZ=0x609f0,0x509f0,0x4338
def enc(pt):
    K=0x40 if (pt & 0x0f)<9 else 0x50
    return (pt-K)&0xff
ok=0; bad=0; badsamp=[]
i=0
while i<SZ:
    if 0x20<=seg[V+i]<0x7f:
        j=i
        while j<SZ and 0x20<=seg[V+j]<0x7f: j+=1
        if j-i>=4:
            for k in range(i,j):
                pred=enc(seg[V+k]); act=so[O+k]
                if pred==act: ok+=1
                else:
                    bad+=1
                    if len(badsamp)<12: badsamp.append((hex(so[O+k]),seg[V+k],hex(pred)))
        i=j
    else: i+=1
print('hit=%d miss=%d'%(ok,bad))
print('miss samples (ct,pt,pred):', badsamp)
