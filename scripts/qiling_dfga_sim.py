# -*- coding: utf-8 -*-
"""QL 拟frida: 跑 libDfga_Catch.so 的 init_array + JNI_OnLoad, 挂 dl_iterate_phdr/open/syscall/exit 桩, 看它扫什么。"""
import sys, struct
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
SO=r"D:\qwork\libDfga_Catch.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB=0x50000000; HEAP=0x51000000; STK=0x60000000; STKSZ=0x100000; SENT=0x6f000000
SYS={167:'prctl',117:'ptrace',129:'kill',131:'tgkill',93:'exit',94:'exit_group',172:'getpid',
     178:'gettid',56:'openat',48:'faccessat',79:'newfstatat',78:'readlinkat',63:'read',64:'write',
     226:'mprotect',222:'mmap',215:'munmap',98:'futex',221:'execve',160:'uname',113:'clock_gettime',
     174:'rt_sigaction',135:'rt_sigprocmask',134:'rt_sigprocmask',96:'set_tid_address',99:'set_robust_list',261:'prlimit64'}
HITS={}
def hit(k):
    HITS[k]=HITS.get(k,0)+1
    if HITS[k]<=8: print('   [HOOK]',k)

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
print('base=0x%x'%base)
ql.mem.map(STUB,0x400000); ql.mem.map(HEAP,0x8000000); ql.mem.map(STK,STKSZ); ql.mem.map(SENT,0x1000)
TLS=HEAP+0x700000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
f=open(SO,'rb'); elf=ELFFile(f); raw=f.read()
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
dyn=elf.get_section_by_name('.dynsym')
stub_by_sym={}; n=[0]
def alloc_stub(nm):
    if nm not in stub_by_sym:
        a=STUB+n[0]*0x10; ql.mem.write(a,b"\xc0\x03\x5f\xd6"); stub_by_sym[nm]=a; n[0]+=1
    return stub_by_sym[nm]
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn','.rela.plt','.rel.plt'):
        for rel in sec.iter_relocations():
            s=dyn.get_symbol(rel['r_info_sym'])
            if s['st_shndx']=='SHN_UNDEF' and s.name: alloc_stub(s.name)
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn'):
        for rel in sec.iter_relocations():
            off=rel['r_offset']; typ=rel['r_info_type']; add=rel['r_addend'] if sec.is_RELA() else 0
            if typ==1027: ql.mem.write(base+off, ql.pack64((base+add)&0xFFFFFFFFFFFFFFFF))
            elif typ in (1024,1025,1026):
                s=dyn.get_symbol(rel['r_info_sym'])
                v=alloc_stub(s.name) if s['st_shndx']=='SHN_UNDEF' else (base+s['st_value']+add)
                ql.mem.write(base+off, ql.pack64(v&0xFFFFFFFFFFFFFFFF))
try:
    DT={t.entry.d_tag:t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags()}
    if 'DT_ANDROID_RELR' in DT:
        ro=DT['DT_ANDROID_RELR']; rs=DT['DT_ANDROID_RELRSZ']
        ents=[struct.unpack_from('<Q',raw,ro+i*8)[0] for i in range(rs//8)]
        locs=[]; w=0
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
        print('RELR',len(locs))
except Exception as e: print('RELR',e)
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.plt','.rel.plt'):
        for rel in sec.iter_relocations():
            s=dyn.get_symbol(rel['r_info_sym'])
            ql.mem.write(base+rel['r_offset'], ql.pack64(stub_by_sym.get(s.name, STUB)))
print('stubs',n[0])
def _pc(q): q.arch.regs.pc=q.arch.regs.x30
def rd(q,addr,l=128):
    try: return q.mem.read(addr,l).split(b'\x00')[0].decode('latin1')
    except: return '?'
def rstr(q,r): 
    try: return rd(q,q.arch.regs.__getattribute__('x%d'%r))
    except: return '?'
ALLO={'p':HEAP+0x600000}
def mk_sys(nm):
    def cb(q):
        hit(nm)
        r=q.arch.regs
        if nm in ('exit','_exit','exit_group','abort'): raise SystemExit('exit called')
        if nm=='syscall':
            nr=r.x8; name=SYS.get(nr,'sys%d'%nr); hit('syscall:'+name)
            if name in ('prctl','ptrace'): print('      syscall',name,'a0=0x%x a1=0x%x'%(r.x0,r.x1))
        r.x0=0; _pc(q)
    return cb
def h_str(nm):
    def cb(q):
        hit(nm+'('+rstr(q,0)+')')
        q.arch.regs.x0=0; _pc(q)
    return cb
def h_struct(nm):
    def cb(q):
        hit(nm+'('+rstr(q,0)+')')
        q.arch.regs.x0=(1<<64)-1; _pc(q)
    return cb
SPECIAL={'dl_iterate_phdr':h_struct,'open':h_struct,'__open_2':h_struct,'openat':h_struct,'access':h_struct,
         'stat':h_struct,'fstat':h_struct,'lstat':h_struct,'fopen':h_struct,'readlink':h_struct,'opendir':h_struct,
         'malloc':lambda q:(setattr(q.arch.regs,'x0',ALLO.__setitem__('p',(ALLO['p']+ (q.arch.regs.x0 or 1)+0x10)&~0xF) or ALLO['p']), _pc(q)),
         'exit':mk_sys('exit'),'_exit':mk_sys('_exit'),'abort':mk_sys('abort'),'syscall':mk_sys('syscall'),
         'prctl':mk_sys('prctl'),'ptrace':mk_sys('ptrace')}
for nm,a in stub_by_sym.items():
    cb=SPECIAL.get(nm) or mk_sys(nm)
    try: ql.hook_address(cb, a)
    except Exception: pass
# 跑 init_array
try:
    ia=elf.get_section_by_name('.init_array')
    if ia:
        for i in range(0, ia['sh_size'], 8):
            fn=struct.unpack_from('<Q', raw, ia['sh_offset']+i)[0]
            try: ql.run(begin=base+fn, end=SENT, timeout=2_000_000)
            except SystemExit as e: print('init 中止:',e); break
            except Exception as e: print('init end',type(e).__name__,str(e)[:60])
except Exception as e: print('init_array err',e)
# JNI_OnLoad(env, vm)
jni=[s for s in dyn.iter_symbols() if s.name=='JNI_OnLoad']
if jni:
    r=ql.arch.regs
    for k in range(31):
        try: r.__setattr__('x%d'%k,0)
        except: pass
    r.x0=STUB; r.x1=STUB; r.sp=STK+STKSZ-0x1000; r.x30=SENT
    print('跑 JNI_OnLoad @0x%x'%(base+jni[0]['st_value']))
    try: ql.run(begin=base+jni[0]['st_value'], end=SENT, timeout=3_000_000)
    except Exception as e: print('JNI_OnLoad end',type(e).__name__,str(e)[:70])
print('\n命中统计:',HITS)
