import re,os
D=r'C:\Users\20751\Desktop\异环\unpacked\dex'
kws=[b'CertificatePinner', b'pin-sha256', b'sha256/', b'setSSLSocketFactory', b'checkServerTrusted']
for fn in ['classes4.dex','classes5.dex','classes3.dex']:
    b=open(os.path.join(D,fn),'rb').read()
    print('==== '+fn+' ====')
    for kw in kws:
        i=b.find(kw)
        while i>=0:
            seg=b[max(0,i-44):i+64]
            strs=[s.decode('latin1') for s in re.findall(rb'[\x20-\x7e]{4,}',seg)]
            print('  '+kw.decode()+': '+' | '.join(strs)[:170])
            i=b.find(kw,i+1)
