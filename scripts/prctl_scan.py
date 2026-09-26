# -*- coding: utf-8 -*-
"""全 SO: prctl/ptrace 调用点 + w0 立即数。"""
import os, struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
W=r"C:\Users\20751\Desktop\异环\unpacked\so"
LAB={1:"PR_SET_PDEATHSIG",2:"PR_GET_DUMPABLE",4:"PR_SET_NAME",15:"PR_SET_NAME?",21:"PR_SET_DUMPABLE",
     22:"PR_GET?DMP",35:"PR_SET_PTRACER_ANY?",39:"PR_SET_PTRACER",20:"PR_MCE_KILL?"}
PT={0:"PTRACE_TRACEME",16:"PTRACE_ATTACH",3:"PTRACE_PEEKDATA",12:"PTRACE_GETREGS",31:"PTRACE_SYSCALL"}
def rdw(words,off): return words[off]
def scan(so):
    p=os.path.join(W,so); raw=open(p,"rb").read(); f=open(p,"rb"); elf=ELFFile(f)
    dyn=elf.get_section_by_name('.dynsym'); got={}
    for sec in elf.iter_sections():
        if isinstance(sec,RelocationSection):
            for rel in sec.iter_relocations():
                s=dyn.get_symbol(rel['r_info_sym'])
                if s.name: got[rel['r_offset']]=s.name
    segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
    rx=[s for s in segs if s[3]&1][0]; off,va,fs,fl=rx
    words=struct.unpack_from("<%dI"%(fs//4),raw,off); N=len(words)
    # PLT 桩 -> sym
    stub={}
    for i in range(N-3):
        w=words[i]
        if (w&0x9F000000)==0x90000000 and ((w&0x1F)==16):
            w2=words[i+1]
            if (w2&0xFFC00000)==0xF9400000 and (((w2>>5)&0x1F)==16) and ((w2&0x1F)==17):
                immlo=(w>>29)&3; immhi=(w>>5)&0x7FFFF; a=immlo|(immhi<<2)
                if a>=(1<<20): a-=(1<<21)
                ga=((va+i*4)&~0xFFF)+(a<<12)+(((w2>>10)&0xFFF)*8)
                nm=got.get(ga)
                if nm: stub[i]=nm
    out={}
    for i in range(N):
        w=words[i]
        if (w&0xFC000000)==0x94000000:
            imm=w&0x03FFFFFF
            if imm>=(1<<25): imm-=(1<<26)
            idx=((va+i*4)+(imm<<2)-va)//4
            if idx in stub and stub[idx] in ("prctl","ptrace"):
                sym=stub[idx]; w0=None
                for k in range(i-1,max(0,i-15),-1):
                    ww=words[k]
                    if (ww&0xFF800000)==0x52800000 and (ww&0x1F)==0:  # movz w0,#imm
                        w0=(ww>>5)&0xFFFF; break
                    if (ww&0xFF800000)==0x72800000 and (ww&0x1F)==0:  # movk -> 组合
                        w0=(((ww>>5)&0xFFFF)<<(((ww>>21)&3)*16)) | (w0 or 0)
                out.setdefault(sym,[]).append((va+i*4,w0))
    print(f"\n### {so}")
    for sym,c in out.items():
        for a,w0 in c[:12]:
            tag=(LAB if sym=="prctl" else PT).get(w0,"?")
            print(f"  {sym} @0x{a:x}  w0={w0} ({tag})")
    f.close()
for so in ["libthemis.so","libsecsdk.so","libmxcore.so","libUnreal.so","libclient.so","libDfga_Catch.so"]:
    try: scan(so)
    except Exception as e: print(so,"err",repr(e))
