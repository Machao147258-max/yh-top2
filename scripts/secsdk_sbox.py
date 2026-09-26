# -*- coding: utf-8 -*-
"""在 libsecsdk 里找 256 字节置换表(S-box) + 用它逆解 .data。"""
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
# 扫 256 字节置换
sboxes=[]
for s in elf.iter_sections():
    if s['sh_type']=='SHT_NOBITS' or s['sh_size']<256: continue
    d=s.data()
    for off in range(0,len(d)-256,1):
        w=d[off:off+256]
        if len(set(w))==256:  # 是 0..255 的置换
            sboxes.append((s.name, s['sh_addr']+off))
print("S-box 候选(任意256窗口若为置换则报, 可能误报):")
for sec,a in sboxes[:20]: print(f"  {sec} @0x{a:x}")
if not sboxes: print("  未找到")

# 无条件试: 若 .data 是异或某单字节再过S盒—先试常见: 直接看 .data 是否有 256 排列
dt=elf.get_section_by_name('.data'); dd=dt.data(); db=dt['sh_addr']
print(f"\n.data 有 {len(dd)} 字节, 是否含完整0..255子集: {len(set(dd))}")
# 试: 把可打印乱码当 单字节-XOR + 位置无关, 用英文频率打分(整段)
import string
FREQ={'e':12.7,'t':9.1,'a':8.2,'o':7.5,'i':7.0,'n':6.7,'s':6.3,'h':6.1,'r':6.0}
def sc(dec):
    s=sum(FREQ.get(chr(c),0) for c in dec if 97<=c<=122)
    return s
best=[]
for k in range(256):
    dec=bytes(c^k for c in dd)
    best.append((sc(dec),k))
best.sort(reverse=True)
print("单字节XOR top5:", [(round(s,1),hex(k)) for s,k in best[:5]])
# 试试 反序/高低半字节交换
for name,fn in [("swap nib",lambda c:((c<<4)|(c>>4))&0xff), ("bitrev",lambda c:int(f'{c:08b}'[::-1],2))]:
    dec=bytes(fn(c) for c in dd)
    print(f"{name} 英文分:", round(sc(dec),1), dec[:40])
f.close()
