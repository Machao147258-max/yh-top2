# -*- coding: utf-8 -*-
"""从运行时镜像 seg.bin 提取解密串表 + 段感知差异统计。"""
import re
from elftools.elf.elffile import ELFFile
seg=open(r"C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin","rb").read()
disk=open(r"D:\qwork\libsecsdk.so","rb").read()
f=open(r"D:\qwork\libsecsdk.so","rb"); elf=ELFFile(f)
segs=[]
for s in elf.iter_segments():
    if s['p_type']=='PT_LOAD': segs.append((s['p_vaddr'],s['p_offset'],s['p_filesz'],s['p_memsz']))
def rt2file(va):
    for v,o,fsz,msz in segs:
        if v<=va<v+fsz: return o+(va-v)
    return None
# 段感知差异统计
tot=diffruns=[]
i=0
diffs=0; comp=0
for va in range(0, min(len(seg), segs[-1][0]+segs[-1][3])):
    fo=rt2file(va)
    if fo is None or fo>=len(disk): continue
    comp+=1
    if seg[va]!=disk[fo]: diffs+=1; diffruns.append(va)
print(f"段感知逐字节: 可比 {comp} 字节, 差异 {diffs} ({100.0*diffs/max(comp,1):.1f}%)")
# 差异区间
if diffruns:
    runs=[]; st=diffruns[0]; pr=diffruns[0]
    for x in diffruns[1:]:
        if x==pr+1: pr=x
        else: runs.append((st,pr)); st=x; pr=x
    runs.append((st,pr))
    print("差异区间(前20):")
    for a,b in runs[:20]: print(f"  0x{a:x}-0x{b:x} ({b-a+1} B)")
    print(f"  共 {len(runs)} 段")

# 提取解密串（8+ 可打印）并保存
strs=[m.group().decode('latin1') for m in re.finditer(rb"[\x20-\x7e]{8,}", seg)]
open(r"C:\Users\20751\Desktop\异环\unidbg\secsdk_decrypted_strings.txt","w",encoding="utf-8").write("\n".join(strs))
print(f"\n解密镜像 8+ 串: {len(strs)}  -> secsdk_decrypted_strings.txt")
# 只看 vmp/netease 相关
for s in strs:
    if any(k in s for k in ("mutivmp","Interpret","ReferenceTable","Dex","netease","yidun","sdkwrapper","loadClass","Separator","VmHelper","kNumPacked")):
        print("  ",s)
