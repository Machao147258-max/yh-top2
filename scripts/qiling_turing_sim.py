# -*- coding: utf-8 -*-
"""QL 拟frida: 跑 libturingmfa.so (图灵盾原生) 的 init+JNI_OnLoad, hook 它导入的文件/proc/popen/getenv/syscall, 看它扫什么。"""
import sys, struct
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
SO=r"D:\qwork\libturingmfa.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB=0x50000000; HEAP=0x51000000; STK=0x60000000; STKSZ=0x100000; SENT=0x6f000000
SYS={167:'prctl',117:'ptrace',56:'openat',48:'faccessat',79:'newfstatat',78:'readlinkat',63:'read',64:'write',172:'getpid',178:'gettid',29:'ioctl',98:'futex',222:'mmap',215:'munmap',261:'prlimit64',160:'uname'}
HITS={}; LOG=[]
def hit(k):
    HITS[k]=HITS.get(k,0)+1
    if HITS[k]<=15: print('   [HOOK]',k); LOG.append(k)
ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address; print('base=0x%x'%base)
ql.mem.map(STUB,0x400000); ql.mem.map(HEAP,0x8000000); ql.mem.map(STK,STKSZ); ql.mem.map(SENT,0x1000)
TLS=HEAP+0x700000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
f=open(SO,'rb'); elf=ELFFile(f); raw=f.read()
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
dyn=elf.get_section_by_name('.dynsym')
stub={}; n=[0]
def A(nm):
    if nm not in stub:
        a=STUB+n[0]*0x10; ql.mem.write(a,b"\xc0\x03\x5f\xd6"); stub[nm]=a; n[0]+=1
    return stub[nm]
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn','.rela.plt','.rel.plt'):
        for rel in sec.iter_relocations():
            s=dyn.get_symbol(rel['r_info_sym'])
            if s['st_shndx']=='SHN_UNDEF' and s.name: A(s.name)
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn'):
        for rel in sec.iter_relocations():
            off=rel['r_offset']; t=rel['r_info_type']; add=rel['r_addend'] if sec.is_RELA() else 0
            if t==1027: ql.mem.write(base+off, ql.pack64((base+add)&0xFFFFFFFFFFFFFFFF))
            elif t in (1024,1025,1026):
                s=dyn.get_symbol(rel['r_info_sym']); v=A(s.name) if s['st_shndx']=='SHN_UNDEF' else (base+s['st_value']+add)
                ql.mem.write(base+off, ql.pack64(v&0xFFFFFFFFFFFFFFFF))
try:
    DT={t.entry.d_tag:t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags()}
    if 'DT_ANDROID_RELR' in DT:
        ro=DT['DT_ANDROID_RELR']; rs=DT['DT_ANDROID_RELRSZ']
        ents=[struct.unpack_from('<Q',raw,ro+i*8)[0] for i in range(rs//8)]; locs=[]; w=0
        for e in ents:
            if e&1==0: w=e; locs.append(w); w+=8
            else:
                for i in range(63):
                    if e&(2<<i): locs.append(w+i*8)
                w+=63*8
        for v,fs,o,fl in segs:
            if not (fl&2): continue
            buf=bytearray(ql.mem.read(base+v,fs))
            for loc in locs:
                if v<=loc<v+fs:
                    oo=loc-v; val=struct.unpack_from('<Q',buf,oo)[0]
                    if val: struct.pack_into('<Q',buf,oo,(base+val)&0xFFFFFFFFFFFFFFFF)
            ql.mem.write(base+v,bytes(buf))
except Exception as e: pass
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.plt','.rel.plt'):
        for rel in sec.iter_relocations():
            s=dyn.get_symbol(rel['r_info_sym']); ql.mem.write(base+rel['r_offset'], ql.pack64(stub.get(s.name,STUB)))
print('stubs',n[0])
def _pc(q): q.arch.regs.pc=q.arch.regs.x30
def rstr(q,r):
    try:
        a=q.arch.regs.__getattribute__('x%d'%r); s=b''
        for i in range(300):
            c=q.mem.read(a+i,1)
            if c==b'\x00': break
            s+=c
        return s.decode('latin1')
    except: return '?'
def mkrw(nm,x0):
    def cb(q):
        hit(nm+'('+rstr(q,0)+')'); q.arch.regs.x0=x0; _pc(q)
    return cb
SPECIAL={}
for nm in ['access','open','openat','fopen','stat','lstat','readlink','opendir','closedir','popen','system','getenv','__system_property_get','readlinkat','statfs']:
    SPECIAL[nm]=mkrw(nm,0)  # 都返回 0/NULL, 只记录参数
def sys_cb(q):
    r=q.arch.regs; nm=SYS.get(r.x8,'sys%d'%r.x8); hit('syscall:'+nm)
    if nm in ('prctl','ptrace'): print('      ',nm,'a0=0x%x a1=0x%x'%(r.x0,r.x1))
    r.x0=0; _pc(q)
SPECIAL['syscall']=sys_cb
ALLO={'p':HEAP+0x600000}
def h_malloc(q):
    n=q.arch.regs.x0 or 1; p=ALLO['p']; ALLO['p']=(ALLO['p']+n+0x10)&~0xF; q.arch.regs.x0=p; _pc(q)
def h_calloc(q):
    n=(q.arch.regs.x0*q.arch.regs.x1) or 1; p=ALLO['p']
    try: q.mem.write(p,b'\x00'*n)
    except: pass
    ALLO['p']=(ALLO['p']+n+0x10)&~0xF; q.arch.regs.x0=p; _pc(q)
def h_realloc(q):
    n=q.arch.regs.x1 or 1; p=ALLO['p']; ALLO['p']=(ALLO['p']+n+0x10)&~0xF; q.arch.regs.x0=p; _pc(q)
def h_free(q): _pc(q)
def h_memcpy(q):
    d,s,n=q.arch.regs.x0,q.arch.regs.x1,q.arch.regs.x2
    try: q.mem.write(d,q.mem.read(s,n))
    except: pass
    q.arch.regs.x0=d; _pc(q)
def h_memset(q):
    d,v,n=q.arch.regs.x0,q.arch.regs.x1&0xff,q.arch.regs.x2
    try: q.mem.write(d,bytes([v])*n)
    except: pass
    q.arch.regs.x0=d; _pc(q)
def h_strlen(q):
    s=q.arch.regs.x0; i=0
    try:
        while q.mem.read(s+i,1)!=b'\x00': i+=1
    except: pass
    q.arch.regs.x0=i; _pc(q)
def h_strcpy(q):
    d,s=q.arch.regs.x0,q.arch.regs.x1; i=0
    try:
        while True:
            b=q.mem.read(s+i,1); q.mem.write(d+i,b)
            if b==b'\x00': break
            i+=1
    except: pass
    q.arch.regs.x0=d; _pc(q)
def h_strcmp(q):
    a,b=q.arch.regs.x0,q.arch.regs.x1; i=0; r=0
    try:
        while True:
            ca=q.mem.read(a+i,1)[0]; cb=q.mem.read(b+i,1)[0]
            if ca!=cb: r=ca-cb; break
            if ca==0: break
            i+=1
    except: pass
    q.arch.regs.x0=r; _pc(q)
def h_strstr(q):
    h,n=q.arch.regs.x0,q.arch.regs.x1
    try:
        hs=q.mem.read(h,256).split(b'\x00')[0]; ns=q.mem.read(n,64).split(b'\x00')[0]
        idx=hs.find(ns); q.arch.regs.x0=(h+idx) if idx>=0 else 0
    except: q.arch.regs.x0=0
    _pc(q)
SPECIAL.update({'malloc':h_malloc,'calloc':h_calloc,'realloc':h_realloc,'free':h_free,'memcpy':h_memcpy,'memmove':h_memcpy,'memset':h_memset,'strlen':h_strlen,'strcpy':h_strcpy,'strncpy':h_strcpy,'strcmp':h_strcmp,'strstr':h_strstr,
 '_Znwm':h_malloc,'_Znam':h_malloc,'_ZdlPv':h_free,'_ZdaPv':h_free,'__stack_chk_fail':h_free})
SPECIAL['exit']=lambda q:(_ for _ in ()).throw(SystemExit()) if False else (q.arch.regs.__setattr__('pc',q.arch.regs.x30),)
def mk(nm):
    def cb(q): hit(nm); q.arch.regs.x0=0; _pc(q)
    return cb
for nm,a in stub.items():
    try: ql.hook_address(SPECIAL.get(nm) or mk(nm), a)
    except Exception: pass
try:
    ia=elf.get_section_by_name('.init_array')
    if ia:
        for i in range(0, ia['sh_size'], 8):
            fn=struct.unpack_from('<Q', raw, ia['sh_offset']+i)[0]
            print('init @0x%x'%(base+fn))
            try: ql.run(begin=base+fn, end=SENT, timeout=2_000_000)
            except Exception as e: print('  init end',type(e).__name__,str(e)[:60])
except Exception as e: print('init err',e)
jni=[s for s in dyn.iter_symbols() if s.name=='JNI_OnLoad']
if jni:
    for k in range(31):
        try: ql.arch.regs.__setattr__('x%d'%k,0)
        except: pass
    ql.arch.regs.x0=STUB; ql.arch.regs.x1=STUB; ql.arch.regs.sp=STK+STKSZ-0x1000; ql.arch.regs.x30=SENT
    print('run JNI_OnLoad @0x%x'%(base+jni[0]['st_value']))
    try: ql.run(begin=base+jni[0]['st_value'], end=SENT, timeout=4_000_000)
    except Exception as e: print('JNI_OnLoad end',type(e).__name__,str(e)[:70])
print('\n命中:',HITS)
