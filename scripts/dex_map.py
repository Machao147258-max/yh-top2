# -*- coding: utf-8 -*-
"""扫每个 dex: map_list 各 section + 声明末尾之后是否有附加 blob(易盾 SepData 可能在此)。"""
import os,struct
D=r"C:\Users\20751\Desktop\异环\unpacked\dex"
TYPE={0x0000:"header",0x0001:"string_id",0x0002:"type_id",0x0003:"proto_id",0x0004:"field_id",
0x0005:"method_id",0x0006:"class_def",0x0007:"call_site_id",0x0008:"method_handle",
0x1000:"map_list",0x1001:"type_list",0x1002:"annotation_set_ref",0x1003:"annotation_set",
0x2000:"class_data",0x2001:"code",0x2002:"string_data",0x2003:"debug_info",
0x2004:"annotation",0x2005:"annotations_directory",0x2006:"encoded_array",0xF000:"hiddenapi"}
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".dex"): continue
    b=open(os.path.join(D,fn),"rb").read()
    fsize=len(b)
    map_off=struct.unpack_from("<I",b,0x34)[0]
    n=struct.unpack_from("<I",b,map_off)[0]
    print(f"\n=== {fn} size={fsize} map@{map_off:x} items={n} ===")
    maxend=0
    items=[]
    for i in range(n):
        off=map_off+4+i*12
        t=struct.unpack_from("<H",b,off)[0]
        cnt=struct.unpack_from("<I",b,off+4)[0]
        o=struct.unpack_from("<I",b,off+8)[0]
        items.append((o,t,cnt))
    items.sort()
    for j,(o,t,cnt) in enumerate(items):
        nxt=items[j+1][0] if j+1<len(items) else fsize
        print(f"  @0x{o:08x} {TYPE.get(t,hex(t)):20s} n={cnt:6d}  span~{nxt-o}")
        maxend=max(maxend,nxt)
    print(f"  最后 item 覆盖到 0x{maxend:x}; 文件尾 0x{fsize:x}; 尾部剩余 {fsize-maxend} 字节")
    if fsize-maxend>16:
        tail=b[maxend:maxend+64]
        print("  尾部:", tail[:48].hex())
