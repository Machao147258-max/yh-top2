# -*- coding: utf-8 -*-
"""Qiling: 追踪 libsecsdk 在 libc 层实际调用(哪些函数+字符串参数)。"""
import sys, struct
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
SO=r"D:\qwork\libsecsdk.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB=0x50000000; HEAP=0x51000000; STK=0x60000000; STKSZ=0x100000; SENT=0x6f000000
STRFUN={'fopen':1,'stat':1,'access':1,'open':1,'fprintf':2,'puts':1,'sprintf':2,'strstr':1,'strcmp':1,
        'strcpy':1,'mkdir':1,'utime':1,'getcwd':1,'fwrite':1,'vsnprintf':3,'uncompress':3,'dlopen':1,'dlsym':2}
def cstr(ql,addr,n=80):
    try:
        b=ql.mem.read(addr,n); return b.split(b"\x00")[0].decode('latin1')
    except: return '?'
ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
ql.mem.map(STUB,0x300000); ql.mem.map(HEAP,0x1000000); ql.mem.map(STK,STKSZ); ql.mem.map(SENT,0x1000)
TLS=HEAP+0x800000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
dyn=elf.get_section_by_name('.dynsym')
stub={}; n=0
def alloc(nm):
    global n
    if nm not in stub: stub[nm]=STUB+n*0x10; ql.mem.write(stub[nm],b"\xc0\x03\x5f\xd6"); n+=1
    return stub[nm]
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn','.rela.plt','.rel.plt'):
        for r in sec.iter_relocations():
            s=dyn.get_symbol(r['r_info_sym'])
            if s['st_shndx']=='SHN_UNDEF' and s.name: alloc(s.name)
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn'):
        for r in sec.iter_relocations():
            t=r['r_info_type']; off=r['r_offset']; add=r['r_addend'] if r.is_RELA() else 0
            if t==1027: ql.mem.write(base+off, ql.pack64((base+add)&0xFFFFFFFFFFFFFFFF))
            elif t in (1024,1025,1026):
                s=dyn.get_symbol(r['r_info_sym'])
                v=alloc(s.name) if s['st_shndx']=='SHN_UNDEF' else (base+s['st_value'])
                ql.mem.write(base+off, ql.pack64(v))
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.plt','.rel.plt'):
        for r in sec.iter_relocations():
            s=dyn.get_symbol(r['r_info_sym'])
            v=stub.get(s.name) or (base+s['st_value'] if s['st_shndx']!='SHN_UNDEF' else STUB)
            ql.mem.write(base+r['r_offset'], ql.pack64(v))
print(f"符号桩 {n}")
HITS={}
def mk(nm):
    def cb(q):
        r=q.arch.regs; HITS[nm]=HITS.get(nm,0)+1
        if HITS[nm]<=3:
            extra=''
            if nm in STRFUN:
                idx=STRFUN[nm]; arg=[r.x0,r.x1,r.x2,r.x3][idx-1] if idx<=4 else r.x0
                # 取含字符串的那个参数
                for ai in range(4):
                    av=[r.x0,r.x1,r.x2,r.x3][ai]
                    if av and 0x51000000<=av<0x52000000:
                        s=cstr(q,av)
                        if s and s.isprintable() and 2<len(s)<80: extra+=' "%s"'%s
            print(f"  [libc] {nm}({HITS[nm]}){extra}")
        r.x0=0; r.pc=r.x30
    return cb
for nm,a in stub.items(): ql.hook_address(mk(nm), a)
# fake JavaVM/JNIEnv
VT=HEAP+0x41000; ql.mem.write(HEAP+0x40000, ql.pack64(VT))
for i in range(0x40): ql.mem.write(VT+i*8, ql.pack64(STUB))
JVM=HEAP+0x40000
jni=[s for s in dyn.iter_symbols() if s.name=='JNI_OnLoad'][0]['st_value']
print(f"跑 JNI_OnLoad @0x{jni:x}")
r=ql.arch.regs
for k in range(31):
    try: setattr(r,f'x{k}',0)
    except: pass
r.x0=JVM; r.sp=STK+STKSZ-0x1000; r.x30=SENT
try: ql.emu_start(base+jni, SENT, timeout=5_000_000, count=2_000_000)
except Exception as e: print("结束:", type(e).__name__, str(e)[:70])
print("\nlibc 调用统计:", dict(sorted(HITS.items(), key=lambda x:-x[1])))
f.close()
