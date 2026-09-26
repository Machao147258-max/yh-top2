# -*- coding: utf-8 -*-
"""从 libthemis.so 抠出内嵌 DEX @0xcd4b0 并列类。"""
import struct
SO=r"D:\qwork\libthemis.so"
b=open(SO,"rb").read()
off=0xcd4b0
magic=b[off:off+8]
fsz=struct.unpack_from("<I",b,off+0x20)[0]
print("magic",magic,"declared size",hex(fsz))
dex=b[off:off+fsz]
open(r"D:\qwork\themis_embedded.dex","wb").write(dex)
print("写出 themis_embedded.dex",len(dex))
# 用 androguard 列类
try:
    from loguru import logger as _lg; _lg.remove()
except Exception: pass
from androguard.core.dex import DEX
d=DEX(dex)
cs=d.get_classes()
print("类数",len(cs))
for c in cs[:40]:
    print("  ",c.get_name())
