# -*- coding: utf-8 -*-
"""PLT-aware: 找检测导入的真实调用者 (bl -> PLT桩 -> GOT)。"""
import struct, numpy as np, capstone, os
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
W=r"C:\Users\20751\Desktop\异环"
def analyze(name, targets, maxshow=8):
    p=os.path.join(W,"unpacked","so",name)
    raw=open(p,"rb").read(); f=open(p,"rb"); elf=ELFFile(f)
    dyn=elf.get_section_by_name('.dynsym')
    got={}
    for sec in elf.iter_sections():
        if isinstance(sec,RelocationSection):
            for rel in sec.iter_relocations():
                s=dyn.get_symbol(rel['r_info_sym'])
                if s.name: got[rel['r_offset']]=s.name
    segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
    rx=[s for s in segs if s[3]&1][0]
    off,rva,rfs,_=rx
    words=np.frombuffer(raw[off:off+rfs],dtype="<u4"); n=len(words)
    idx=np.arange(n,dtype=np.int64); pcs=(rva+idx*4).astype(np.int64)
    is_adrp=(words&0x9F000000)==0x90000000
    immlo=((words>>29)&3).astype(np.int64); immhi=((words>>5)&0x7FFFF).astype(np.int64)
    imm=immlo|(immhi<<2); imm=np.where(imm>=(1<<20),imm-(1<<21),imm)<<12
    adt=((pcs&~0xFFF)+imm).astype(np.int64); rd=(words&0x1F).astype(np.int64)
    is_ldr=(words&0xFFC00000)==0xF9400000; ldr_imm=((words>>10)&0xFFF)*8; ldr_rn=((words>>5)&0x1F)
    # PLT 桩: adrp x16; ldr x17,[x16,#lo]; ...
    stubs={}
    for i in np.where(is_adrp&(rd==16))[0]:
        for d in (1,):
            j=i+d
            if j<n and is_ldr[j] and ldr_rn[j]==16 and ((words[j]>>0)&0x1F)==17:
                ga=int(adt[i])+int(ldr_imm[j])
                if ga in got: stubs[int(pcs[i])]=got[ga]
    # bl 目标
    is_bl=(words&0xFC000000)==0x94000000
    imm26=(words&0x03FFFFFF).astype(np.int64); imm26=np.where(imm26>=(1<<25),imm26-(1<<26),imm26)
    btgt=(pcs+(imm26<<2)).astype(np.int64)
    print(f"\n===== {name} (PLT桩 {len(stubs)}) =====")
    for want in targets:
        sa=[a for a,s in stubs.items() if s==want]
        callers=set()
        for a in sa:
            for i in np.where(is_bl&(btgt==a))[0]:
                callers.add(int(pcs[i])-4)
        print(f"  {want}: 桩={[hex(a) for a in sa]} 真实调用者 {len(callers)}: {[hex(c) for c in sorted(callers)[:maxshow]]}")
    f.close()
analyze("libthemis.so", ["memmem","__system_property_get","prctl","ioctl","readlink","opendir","access","stat","open","fopen"])
analyze("libsecsdk.so", ["dl_iterate_phdr","uncompress","access","strstr","dlopen","dlsym"])
