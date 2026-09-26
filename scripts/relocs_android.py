# -*- coding: utf-8 -*-
"""解析 Android 打包重定位 (DT_ANDROID_RELR + DT_ANDROID_RELA/APS2)。"""
import struct
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libUnreal.so"

def uleb(d,p):
    r=0;s=0
    while True:
        b=d[p];p+=1;r|=(b&0x7f)<<s;s+=7
        if not (b&0x80):break
    return r,p
def sleb(d,p):
    r=0;s=0
    while True:
        b=d[p];p+=1;r|=(b&0x7f)<<s;s+=7
        if not (b&0x80):
            if b&0x40: r|=-(1<<s)
            break
    return r,p

f=open(SO,"rb"); elf=ELFFile(f)
dyn=elf.get_section_by_name('.dynamic')
info={}
for t in dyn.iter_tags():
    info[t.entry.d_tag]=t.entry.d_val
alg = elf.get_section_by_name('.gnu.version_r')  # 无用, 占位
f.seek(0); raw=f.read()
f.close()

# ---- RELR ----
relr_off=info.get('DT_ANDROID_RELR'); relr_sz=info.get('DT_ANDROID_RELRSZ')
print(f"RELR: off={relr_off} size={relr_sz}")
entries=[struct.unpack_from("<Q",raw,relr_off+i*8)[0] for i in range(relr_sz//8)]
print(f"  RELR entries={len(entries)}")
# 展开为偏移列表
locs=[]; where=0
for e in entries:
    if e&1==0:
        where=e; locs.append(where); where+=8
    else:
        for i in range(63):
            if e&(2<<i): locs.append(where+i*8)
        where+=63*8
print(f"  -> 相对重定位地址数={len(locs)}  示例={[hex(x) for x in locs[:5]]}")

# ---- ANDROID_RELA (APS2) ----
ra_off=info.get('DT_ANDROID_RELA'); ra_sz=info.get('DT_ANDROID_RELASZ')
print(f"\nRELA(APS2): off={ra_off} size={ra_sz}")
blob=raw[ra_off:ra_off+ra_sz]
print(f"  magic={blob[:4]}")
p=4
cnt,p=uleb(blob,p)
print(f"  声明 reloc 数={cnt}")
rels=[]; off=0
while p<len(blob):
    gs,p=sleb(blob,p)
    if gs==0: break
    gd,p=sleb(blob,p); off+=gd
    gi,p=sleb(blob,p)
    for j in range(gs):
        add,p=sleb(blob,p)
        rels.append((off+j*8, gi, add))
    off+=gs*8
print(f"  实际解析 reloc 数={len(rels)}")
import collections
tys=collections.Counter(info>>32 if False else (gi & 0xffffffff)*0 for _,gi,_ in rels)
tys=collections.Counter((gi & 0xffffffff) for _,gi,_ in rels)
print(f"  类型分布(低32位 r_info): {dict(tys)}")
print(f"  示例: {[(hex(o),hex(gi),a) for o,gi,a in rels[:5]]}")
