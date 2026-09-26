# -*- coding: utf-8 -*-
import struct,os,json
KNOWN=set()
for row in json.load(open(r"C:\Users\20751\Desktop\异环\scripts\rl_methods.json")):
    if row[4] is not None: KNOWN.add(row[4])
def hits_run(vals):
    # vals: list of ints; find max ascending run of low24 in KNOWN
    best=0; cur=0; prev=-1; start=0; bs=0
    for i,v in enumerate(vals):
        x=v&0xffffff
        if x in KNOWN and x>prev: cur+=1; prev=x
        else: cur=1 if x in KNOWN else 0; prev=x if x in KNOWN else -1; start=i
        if cur>best: best=cur; bs=start
    return best,bs
files=[r"C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin", r"D:\qwork\libsecsdk.so"]+[r"C:\Users\20751\Desktop\异环\unpacked\dex\classes%d.dex"%i for i in range(1,6)]
for p in files:
    if not os.path.exists(p): continue
    b=open(p,"rb").read(); n=(len(b)//4)*4
    vals=list(struct.unpack_from("<%dI"% (n//4), b))
    print(f"\n{p}")
    for stride in (1,2,3,4,6):
        bst,bs=hits_run(vals[::stride])
        if bst>=25:
            o=bs*stride*4
            print(f"  stride={stride} 最长递增命中={bst} @0x{o:x} ids={[vals[(bs+i)*stride]&0xffffff for i in range(min(bst,16))]}")
