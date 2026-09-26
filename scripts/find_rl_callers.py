# -*- coding: utf-8 -*-
"""逐 dex 找 Utils.rL 的 method 索引，再扫 invoke-kind 指令引用(35c: op,A,G,idx_lo,idx_hi)。"""
import struct, os
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
INV={0x6e,0x6f,0x70,0x71,0x72,0x74,0x75,0x76,0x77,0x78}

for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    b=open(os.path.join(D,fn),"rb").read()
    sis,sio=struct.unpack_from("<II",b,0x38)
    tis,tio=struct.unpack_from("<II",b,0x40)
    mis,mio=struct.unpack_from("<II",b,0x58)
    def uleb(o):
        r=0;s=0
        while True:
            x=b[o];o+=1;r|=(x&0x7f)<<s
            if not x&0x80:break
            s+=7
        return r,o
    def gs(i):
        off=struct.unpack_from("<I",b,sio+i*4)[0]; n,o=uleb(off); return b[o:o+n].decode("utf-8","replace")
    def gt(i): return gs(struct.unpack_from("<I",b,tio+i*4)[0])
    # 找 Utils.rL 索引
    tgt=[]
    for i in range(mis):
        cls=struct.unpack_from("<H",b,mio+i*8)[0]
        name=struct.unpack_from("<I",b,mio+i*8+4)[0]
        cn=gt(cls); nm=gs(name)
        if nm in ("rL","showRiskMessage") and ("sdkwrapper" in cn or "netease" in cn):
            tgt.append((i,nm,cn))
    print(f"=== {fn}: Utils 方法={tgt}")
    for idx,nm,cn in tgt:
        lo,hi=idx&0xff,(idx>>8)&0xff
        # 扫 invoke 指令
        hits=[]
        i=0
        while i < len(b)-4:
            op=b[i]
            if op in INV and b[i+2]==lo and b[i+3]==hi:
                hits.append(i)
            i+=1
        print(f"    method#{idx} {nm} 索引字节={lo:02x}{hi:02x}  invoke 命中={len(hits)}")
        for h in hits[:12]:
            ctx=b[h-8:h+6]
            print(f"      @0x{h:x}: {' '.join('%02x'%c for c in ctx)}")
