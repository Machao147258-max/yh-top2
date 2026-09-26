# -*- coding: utf-8 -*-
"""遍历 APK 内所有 lib/arm64-v8a/*.so，扫描 SSL/OpenSSL/pinning 标记（分块）。"""
import zipfile,os
APK=r"C:\Users\20751\Desktop\异环\apk\yh_gw_20260702.apk"
MARK={
 'OpenSSL':[b'OpenSSL 1.',b'openssl/',b'SSL_CTX_new',b'SSL_new',b'SSL_do_handshake',b'ossl_',b'OPENSSL_'],
 'TLS':[b'TLSv1.3',b'TLS_AES',b'TLS 1.',b'SSLv23'],
 'BoringSSL':[b'BoringSSL',b'boringssl',b'conscrypt',b'Conscrypt'],
 'PIN':[b'pin-sha256',b'sha256//',b'pinned public key',b'X509_VERIFY',b'CURLOPT_PINNEDPUBLICKEY',b'checkServerTrusted',b'SSL_CTX_set_verify'],
 'Verify':[b'verify_callback',b'X509_verify_cert',b'SSL_get_verify_result',b'certificate verify failed'],
 'Curl':[b'curl_easy',b'libcurl'],
}
z=zipfile.ZipFile(APK)
libs=[n for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')]
print("libs",len(libs))
for n in sorted(libs):
    info=z.getinfo(n)
    if info.file_size>120*1024*1024:
        print("%-42s SKIP(>120MB %d)"%(os.path.basename(n),info.file_size)); continue
    try: b=z.read(n)
    except Exception as e: print(n,"ERR",e); continue
    hits={}
    for cat,pats in MARK.items():
        c=sum(b.count(p) for p in pats)
        if c: hits[cat]=c
    tag='' if not hits else '  <<< '+str(hits)
    if hits or 'ssl' in os.path.basename(n).lower() or 'crypto' in os.path.basename(n).lower() or 'tcp' in os.path.basename(n).lower() or 'client' in os.path.basename(n).lower():
        print("%-42s %8d%s"%(os.path.basename(n),len(b),tag))
