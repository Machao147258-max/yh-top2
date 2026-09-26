# -*- coding: utf-8 -*-
"""正确解析 DEX：class_defs->class_data->code_item, 定位每个 invoke 属于哪个方法。"""
import struct, os
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
INV={0x6e:"virtual",0x6f:"super",0x70:"direct",0x71:"static",0x72:"interface",
     0x74:"virtual/range",0x75:"super/range",0x76:"direct/range",0x77:"static/range",0x78:"interface/range"}

def parse(fn):
    b=open(os.path.join(D,fn),"rb").read()
    sis,sio=struct.unpack_from("<II",b,0x38)
    tis,tio=struct.unpack_from("<II",b,0x40)
    mis,mio=struct.unpack_from("<II",b,0x58)
    cds,cdo=struct.unpack_from("<II",b,0x60)
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
    def mname(i):
        cls=struct.unpack_from("<H",b,mio+i*8)[0]
        return gt(cls)+"."+gs(struct.unpack_from("<I",b,mio+i*8+4)[0])
    # 目标方法索引
    target={}
    for i in range(mis):
        nm=mname(i)
        if "sdkwrapper/Utils" in nm: target[i]=nm
    # 遍历 code_items -> 方法
    rng=[]  # (start,end,methodname)
    for ci in range(cds):
        off=cdo+ci*32
        cls_idx=struct.unpack_from("<I",b,off)[0]
        cdata=struct.unpack_from("<I",b,off+24)[0]
        cname=gt(cls_idx)
        if cdata==0: continue
        o=cdata
        sf,o=uleb(o); inf,o=uleb(o); dm,o=uleb(o); vm,o=uleb(o)
        for _ in range(sf): _,o=uleb(o); _,o=uleb(o)
        for _ in range(inf): _,o=uleb(o); _,o=uleb(o)
        cur=0
        for _ in range(dm+vm):
            mdiff,o=uleb(o); acc,o=uleb(o); coff,o=uleb(o)
            cur=cur+mdiff
            if coff==0 or cur>=mis: continue
            try:
                regs,insn,outs,tries,dbg,isz=struct.unpack_from("<HHHHII",b,coff)
                rng.append((coff+16,coff+16+isz*2, mname(cur), acc))
            except Exception: pass
    # 找 rL 调用
    for i,nm in target.items():
        lo,hi=i&0xff,(i>>8)&0xff
        hits=[j for j in range(len(b)-4) if b[j] in INV and b[j+2]==lo and b[j+3]==hi]
        print(f"\n### {nm} (#{i})  命中={len(hits)}")
        # 归类到方法
        from collections import Counter
        loc=Counter()
        for h in hits:
            for s,e,mn,acc in rng:
                if s<=h<e: loc[(mn,acc)]+=1; break
        for (mn,acc),c in loc.most_common(20):
            print(f"   {c:3d} x  {mn}  acc=0x{acc:x}")

for fn in sorted(os.listdir(D)):
    if fn.endswith(".dex"): parse(fn)
