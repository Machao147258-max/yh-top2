# -*- coding: utf-8 -*-
"""对比运行时镜像 secsdk_seg.bin 与磁盘 libsecsdk.so，找差异(解密)区。"""
seg=open(r"C:\Users\20751\Desktop\异环\unidbg\secsdk_seg.bin","rb").read()
disk=open(r"D:\qwork\libsecsdk.so","rb").read()
print("seg=",len(seg),"disk=",len(disk))
n=min(len(seg),len(disk))
# 逐 4KB 页统计差异
PS=4096
diff_pages=[]
for p in range(0,n,PS):
    a=seg[p:p+PS]; b=disk[p:p+PS]
    if a!=b:
        d=sum(1 for x,y in zip(a,b) if x!=y)
        diff_pages.append((p,d))
print("差异页数:",len(diff_pages),"总页:",(n+PS-1)//PS)
# 合并连续差异页为区间
runs=[]
for p,d in diff_pages:
    if runs and p==runs[-1][1]+PS: runs[-1][1]=p
    else: runs.append([p,p])
for a,b in runs:
    print(f"  diff 0x{a:x} - 0x{b+PS:x}  ({(b-a)//PS+1} 页)")
# 在运行时镜像里找 'mutivmp' 的地址
i=seg.find(b"mutivmp")
print("runtime 'mutivmp' @0x%x"%i if i>=0 else "no mutivmp in seg")
if i>=0:
    print("  disk同址:", disk[i-8:i+40] if i-8>=0 else b"")
    print("  seg :", seg[i-8:i+40])
