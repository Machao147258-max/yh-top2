# -*- coding: utf-8 -*-
"""轻量 DEX 解析：列类/方法; 找 com/netease/nis/sdkwrapper/Utils 及 rL 调用者。"""
import struct, os
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"

def uleb(b,o):
    r=0;s=0
    while True:
        x=b[o];o+=1;r|=(x&0x7f)<<s
        if not x&0x80: break
        s+=7
    return r,o

class Dex:
    def __init__(s,p):
        s.b=open(p,"rb").read(); b=s.b
        s.string_ids=s.read_ids(8)
        s.type_ids=s.read_ids(0x40)   # {type_ids_size@0x38? } careful
    def read_ids(s,off):
        size,off2=struct.unpack_from("<II",s.b,off)
        return size,off2

def parse(p):
    b=open(p,"rb").read()
    string_ids_size,string_ids_off=struct.unpack_from("<II",b,0x38)
    type_ids_size,type_ids_off=struct.unpack_from("<II",b,0x40)
    proto_ids_size,proto_ids_off=struct.unpack_from("<II",b,0x48)
    field_ids_size,field_ids_off=struct.unpack_from("<II",b,0x50)
    method_ids_size,method_ids_off=struct.unpack_from("<II",b,0x58)
    class_defs_size,class_defs_off=struct.unpack_from("<II",b,0x60)
    def uleb(o):
        r=0;s=0
        while True:
            x=b[o];o+=1;r|=(x&0x7f)<<s
            if not x&0x80:break
            s+=7
        return r,o
    def getstr(i):
        off=struct.unpack_from("<I",b,string_ids_off+i*4)[0]
        n,o=uleb(off)
        return b[o:o+n].decode("utf-8","replace")
    def gettype(i):
        return getstr(struct.unpack_from("<I",b,type_ids_off+i*4)[0])
    return dict(b=b,getstr=getstr,gettype=gettype,
        sis=string_ids_size,sio=string_ids_off,mis=method_ids_size,mio=method_ids_off,
        cds=class_defs_size,cdo=class_defs_off,pis=proto_ids_size,pio=proto_ids_off)

for fn in ["classes.dex"]:
    p=os.path.join(D,fn); X=parse(p); b=X["b"]; getstr=X["getstr"]; gettype=X["gettype"]
    print(f"=== {fn}: str={X['sis']} type={X['sis']} method={X['mis']} class={X['cds']} ===")
    # 找目标类 type idx
    want="Lcom/netease/nis/sdkwrapper/Utils;"
    tgt=None
    for i in range(X["sis"]):
        s=getstr(i)
        if "netease" in s or "sdkwrapper" in s:
            print("  str:",i,repr(s))
    # 找 rL/Utils 的 method_id
    methods=[]
    for i in range(X["mis"]):
        cls=struct.unpack_from("<H",b,X["mio"]+i*8)[0]
        proto=struct.unpack_from("<H",b,X["mio"]+i*8+2)[0]
        name=struct.unpack_from("<I",b,X["mio"]+i*8+4)[0]
        methods.append((cls,proto,name))
    for i,(cls,proto,name) in enumerate(methods):
        cn=gettype(cls)
        if "netease" in cn or "sdkwrapper" in cn:
            print(f"  method[{i}] {cn}.{getstr(name)}")
