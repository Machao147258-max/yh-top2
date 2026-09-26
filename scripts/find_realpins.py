# -*- coding: utf-8 -*-
import os,re,zipfile
def scan(tag,b):
    for m in re.finditer(rb'sha256/[A-Za-z0-9+/=]{20,}', b):
        print('  [%s] @0x%x  %s'%(tag,m.start(),m.group().decode('latin1')[:80]))
    for m in re.finditer(rb'pin-sha256', b):
        seg=b[m.start():m.start()+90]
        print('  [%s] pin-sha256: %s'%(tag,seg.decode('latin1')[:90]))
    for m in re.finditer(rb'sha1/[A-Za-z0-9+/=]{20,}', b):
        print('  [%s] @0x%x  %s'%(tag,m.start(),m.group().decode('latin1')[:60]))
print('== DEX ==')
D=r'C:\Users\20751\Desktop\异环\unpacked\dex'
for fn in sorted(os.listdir(D)):
    if fn.endswith('.dex'): scan(fn, open(os.path.join(D,fn),'rb').read())
print('== .so ==')
for p in [r'D:\qwork\libmxcore.so',r'D:\qwork\libprimekit.so']:
    if os.path.exists(p): scan(os.path.basename(p), open(p,'rb').read())
z=zipfile.ZipFile(r'C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk')
for n in ['lib/arm64-v8a/libPatcherSDK.so','lib/arm64-v8a/libtapsdkcore.so','lib/arm64-v8a/libwm_fascore.so']:
    scan(os.path.basename(n), z.read(n))
print('== libUnreal (stream) ==')
with z.open('lib/arm64-v8a/libUnreal.so') as f:
    prev=b''
    while True:
        ch=f.read(8*1024*1024)
        if not ch: break
        data=prev+ch
        for m in re.finditer(rb'sha256/[A-Za-z0-9+/=]{20,}', data):
            print('  [libUnreal] %s'%m.group().decode('latin1')[:80])
        prev=data[-64:]
