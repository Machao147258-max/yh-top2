# -*- coding: utf-8 -*-
import zipfile,os,re
APK=r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
z=zipfile.ZipFile(APK)
MARK=[b'OpenSSL 1.',b'SSL_CTX_new',b'TLSv1.3',b'BoringSSL',b'conscrypt',b'pin-sha256',b'sha256//',b'pinned public key',b'CURLOPT_PINNEDPUBLICKEY',b'SSL_CTX_set_verify',b'checkServerTrusted']
# 1) 流式扫 libUnreal
name='lib/arm64-v8a/libUnreal.so'
print('=== stream scan libUnreal.so ===')
cnt={m:0 for m in MARK}; total=0
with z.open(name) as f:
    while True:
        ch=f.read(4*1024*1024)
        if not ch: break
        total+=len(ch)
        for m in MARK: cnt[m]+=ch.count(m)
print('size',total,'hits',{m.decode():c for m,c in cnt.items() if c})
# 2) libprimekit pin 上下文
print('\n=== libprimekit.so PIN 上下文 ===')
b=z.read('lib/arm64-v8a/libprimekit.so')
for kw in [b'pin-sha256',b'sha256//',b'pinned public key',b'CURLOPT_PINNEDPUBLICKEY']:
    i=b.find(kw)
    while i>=0:
        seg=b[max(0,i-50):i+70]
        ss=[s.decode('latin1') for s in re.findall(rb'[\x20-\x7e]{5,}',seg)]
        print('  ['+kw.decode()+'] '+' | '.join(ss)[:170])
        i=b.find(kw,i+1)
