# -*- coding: utf-8 -*-
"""定位 检测相关导入 的调用点: adrp+ldr 到 GOT。"""
import struct, numpy as np, capstone, os
from elftools.elf.elffile import ELFFile
W=r"C:\Users\20751\Desktop\异环"
def analyze(name, targets):
    p=os.path.join(W,"unpacked","so",name)
    raw=open(p,"rb").read()
    f=open(p,"rb"); elf=ELFFile(f)
    dyn=elf.get_section_by_name('.dynsym')
    # GOT映射
    got={}
    from elftools.elf.relocation import RelocationSection
    for sec in elf.iter_sections():
        if isinstance(sec,RelocationSection) and sec.name in ('.rela.plt','.rela.dyn','.rel.plt'):
            for rel in sec.iter_relocations():
                s=dyn.get_symbol(rel['r_info_sym'])
                if s.name: got[rel['r_offset']]=s.name
    # 段
    def phdrs():
        eh=raw[:0x40]; e_phoff=struct.unpack_from("<Q",eh,0x20)[0]; e_phnum=struct.unpack_from("<H",eh,0x38)[0]; es=struct.unpack_from("<H",eh,0x36)[0]
        out=[]
        for i in range(e_phnum):
            q=e_phoff+i*es
            if struct.unpack_from("<I",raw,q)[0]!=1: continue
            fl=struct.unpack_from("<I",raw,q+4)[0]; off,va,_pa,fs,ms=struct.unpack_from("<5Q",raw,q+8)
            out.append((off,va,fs,fl))
        return out
    segs=phdrs(); rx=[s for s in segs if s[3]&1][0]
    off,va,fs,fl=rx
    words=np.frombuffer(raw[off:off+fs],dtype="<u4"); n=len(words)
    idx=np.arange(n,dtype=np.int64); pcs=(va+idx*4).astype(np.int64)
    is_adrp=(words&0x9F000000)==0x90000000
    immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
    imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
    adrptgt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
    is_ldr=(words&0xFFC00000)==0xF9400000   # ldr (unsigned offset, 64-bit)
    ldr_imm=((words>>10)&0xFFF)*8; ldr_rn=((words>>5)&0x1F)
    md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    print(f"\n===== {name} =====")
    for want in targets:
        gotaddrs=[a for a,s in got.items() if s==want]
        if not gotaddrs:
            print(f"  {want}: 无 GOT"); continue
        found=[]
        for ga in gotaddrs:
            page=ga&~0xFFF; lo=ga&0xFFF
            hits=np.where(is_adrp&(adrptgt==page))[0]
            for i in hits:
                for d in (1,2):
                    j=i+d
                    if j<n and is_ldr[j] and rd[i]==ldr_rn[j] and int(ldr_imm[j])==lo:
                        found.append(int(pcs[j])); break
        print(f"  {want}: GOT=0x{gotaddrs[0]:x} 调用点 {len(found)}: {[hex(x) for x in found[:8]]}")
    f.close()
analyze("libthemis.so", ["memmem","__system_property_get","prctl","readlink","opendir","ioctl","open","access","stat"])
analyze("libsecsdk.so", ["dl_iterate_phdr","uncompress","access","open","strstr"])
