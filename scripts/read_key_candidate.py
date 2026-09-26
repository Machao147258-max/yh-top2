# -*- coding: utf-8 -*-
import struct
raw=open(r"D:\qwork\libUnreal.so","rb").read()
eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
segs=[]
for i in range(e_phnum):
    q=e_phoff+i*es
    if struct.unpack_from("<I",raw,q)[0]!=1: continue
    fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
    segs.append((off,va,fs,ms,fl))
def v2f(a):
    for o,v,fs,ms,fl in segs:
        if v<=a<v+ms: 
            if a < v+fs: return o+(a-v), ("file" )
            else: return None, ("BSS(未文件)")
    return None,("未映射")
fo,kind=v2f(0xcdbc40)
print(f"0xcdbc40 -> fo={fo} {kind}")
if fo is not None:
    b=raw[fo:fo+48]
    print("32B:", b[:32].hex())
    print("16B:", b[:16].hex())
    print("hex :", b[:32].hex())
# 附近
print("\n附近 0xcdbc20..0xcdbc60:")
fo2,_=v2f(0xcdbc20)
print(raw[fo2:fo2+0x40].hex())
