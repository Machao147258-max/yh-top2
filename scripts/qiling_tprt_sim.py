# -*- coding: utf-8 -*-
"""QL 模拟 Frida: libsecsdk —— 造 fake JavaVM, 钩安全相关导入, 跑 JNI_OnLoad, 看触发啥。"""
import sys, struct
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
SO=r"D:\qwork\libtprt.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB=0x50000000; HEAP=0x51000000; STK=0x60000000; STKSZ=0x100000; SENT=0x6f000000
WATCH={"dl_iterate_phdr","exit","_exit","abort","access","open","__open_2","fopen","strstr",
       "__system_property_get","uncompress","mmap","mprotect","dlopen","dlsym","stat","getcwd","utime"}

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
print(f"base={base:#x}")
ql.mem.map(STUB,0x200000); ql.mem.map(HEAP,0x1000000); ql.mem.map(STK,STKSZ); ql.mem.map(SENT,0x1000)
TLS=HEAP+0x800000; ql.mem.write(TLS+0x28, ql.pack64(0))
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
# ---- 完整重定位: 先给 undef 符号分配桩, 再应用 .rela.dyn / RELR ----
dyn=elf.get_section_by_name('.dynsym')
stub_by_sym={}; n=0
DATA_BUF={}
def alloc_stub(nm):
    global n
    if nm=="__sF":
        if nm not in DATA_BUF:
            a=HEAP+0x700000; ql.mem.write(a,b"\x00"*0x200); DATA_BUF[nm]=a
        return DATA_BUF[nm]
    if nm not in stub_by_sym:
        a=STUB+n*0x10; ql.mem.write(a,b"\xc0\x03\x5f\xd6"); stub_by_sym[nm]=a; n+=1
    return stub_by_sym[nm]
# 先扫所有 undef 符号建桩
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn','.rela.plt','.rel.plt'):
        for rel in sec.iter_relocations():
            sym=dyn.get_symbol(rel['r_info_sym'])
            if sym['st_shndx']=='SHN_UNDEF' and sym.name: alloc_stub(sym.name)
# 应用 .rela.dyn / .rel.dyn
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.dyn','.rel.dyn'):
        for rel in sec.iter_relocations():
            off=rel['r_offset']; typ=rel['r_info_type']; add=rel['r_addend'] if sec.is_RELA() else 0
            if typ==1027:  # RELATIVE
                ql.mem.write(base+off, ql.pack64((base+add)&0xFFFFFFFFFFFFFFFF))
            elif typ in (1024,1025,1026):  # JUMP_SLOT/GLOB_DAT/ABS64
                sym=dyn.get_symbol(rel['r_info_sym'])
                if sym['st_shndx']=='SHN_UNDEF':
                    val=alloc_stub(sym.name)
                else:
                    val=(base+sym['st_value']+add)&0xFFFFFFFFFFFFFFFF
                ql.mem.write(base+off, ql.pack64(val))
print(f"符号桩 {n}")
# RELR
try:
    DT={t.entry.d_tag:t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags()}
    if 'DT_ANDROID_RELR' in DT:
        ro=DT['DT_ANDROID_RELR']; rs=DT['DT_ANDROID_RELRSZ']
        ents=[struct.unpack_from("<Q",raw,ro+i*8)[0] for i in range(rs//8)]
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
                    oo=loc-v; val=struct.unpack_from("<Q",buf,oo)[0]
                    if val: struct.pack_into("<Q",buf,oo,(base+val)&0xFFFFFFFFFFFFFFFF)
            ql.mem.write(base+v,bytes(buf))
        print("RELR",len(locs))
except Exception as e: print("RELR",e)
# .rela.plt GOT -> 桩
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name in ('.rela.plt','.rel.plt'):
        for rel in sec.iter_relocations():
            sym=dyn.get_symbol(rel['r_info_sym'])
            ql.mem.write(base+rel['r_offset'], ql.pack64(stub_by_sym.get(sym.name, STUB)))
# hook 所有桩: 真实现 malloc/mem* / 字符串, 其余打点+ret0
HITS={}
ALLO={"p":HEAP+0x600000}
def _pc(q): q.arch.regs.pc=q.arch.regs.x30
def h_malloc(q):
    n=q.arch.regs.x0 or 1; p=ALLO["p"]; ALLO["p"]=(ALLO["p"]+n+0x10)&~0xF; q.arch.regs.x0=p; _pc(q)
def h_calloc(q):
    n=q.arch.regs.x0*q.arch.regs.x1 or 1; p=ALLO["p"]
    try: q.mem.write(p,b"\x00"*n)
    except: pass
    ALLO["p"]=(ALLO["p"]+n+0x10)&~0xF; q.arch.regs.x0=p; _pc(q)
def h_realloc(q):
    n=q.arch.regs.x1 or 1; p=ALLO["p"]; ALLO["p"]=(ALLO["p"]+n+0x10)&~0xF; q.arch.regs.x0=p; _pc(q)
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
        while q.mem.read(s+i,1)!=b"\x00": i+=1
    except: pass
    q.arch.regs.x0=i; _pc(q)
def h_strcpy(q):
    d,s=q.arch.regs.x0,q.arch.regs.x1; i=0
    try:
        while True:
            b=q.mem.read(s+i,1); q.mem.write(d+i,b)
            if b==b"\x00": break
            i+=1
    except: pass
    q.arch.regs.x0=d; _pc(q)
def h_strncpy(q):
    d,s,n=q.arch.regs.x0,q.arch.regs.x1,q.arch.regs.x2; i=0
    try:
        while i<n:
            b=q.mem.read(s+i,1); q.mem.write(d+i,b)
            if b==b"\x00": break
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
        hs=q.mem.read(h,256).split(b"\x00")[0]; ns=q.mem.read(n,64).split(b"\x00")[0]
        idx=hs.find(ns); q.arch.regs.x0=(h+idx) if idx>=0 else 0
    except: q.arch.regs.x0=0
    _pc(q)
SPECIAL={"malloc":h_malloc,"calloc":h_calloc,"realloc":h_realloc,"free":h_free,
         "memcpy":h_memcpy,"memmove":h_memcpy,"memset":h_memset,
         "strlen":h_strlen,"strcpy":h_strcpy,"strncpy":h_strncpy,"strcmp":h_strcmp,"strstr":h_strstr}
def mkstub(nm):
    def cb(q):
        HITS[nm]=HITS.get(nm,0)+1
        if HITS[nm]<=5: print(f"  [STUB] {nm} x0={q.arch.regs.x0:#x} x1={q.arch.regs.x1:#x}")
        q.arch.regs.x0=0; _pc(q)
    return cb
for nm,a in stub_by_sym.items():
    ql.hook_address(SPECIAL[nm] if nm in SPECIAL else mkstub(nm), a)
# 自动映射未映射页, 让 JNI_OnLoad 跑到底(别早崩)
try:
    from unicorn import UC_HOOK_MEM_UNMAPPED
    PAGE=0x10000
    def _unmapped(uc, access, addr, size, value, user):
        base=addr & ~(PAGE-1)
        try: uc.mem_map(base, PAGE); return True
        except Exception: return False
    ql.uc.hook_add(UC_HOOK_MEM_UNMAPPED, _unmapped)
    print('auto-map unmapped hooked')
except Exception as e: print('auto-map fail', e)
# hook libtprt 自己的 syscall 引擎 tp_syscall_imp
SYSNAME={56:'openat',57:'close',63:'read',64:'write',48:'faccessat',79:'newfstatat',78:'readlinkat',167:'prctl',117:'ptrace',129:'kill',131:'tgkill',172:'getpid',178:'gettid',29:'ioctl',98:'futex',222:'mmap',215:'munmap',226:'mprotect',160:'uname',221:'execve',220:'clone',96:'set_tid_address',99:'set_robust_list',261:'prlimit64',113:'clock_gettime',169:'getppid',175:'geteuid',134:'rt_sigaction',135:'rt_sigprocmask',260:'wait4',214:'brk'}
SYS={}
def h_tp(q):
    r=q.arch.regs; nr=r.x0
    SYS[nr]=SYS.get(nr,0)+1
    extra=''
    for reg in (r.x2, r.x3, r.x1):
        try:
            s=q.mem.read(reg,160).split(b'\x00')[0]
            t=''.join(chr(c) if 32<=c<127 else '.' for c in s)
            if len(t)>=3 and ('/' in t or t.startswith('/')):
                extra=' path=%r'%t; break
        except: pass
    print('  [tp_syscall_imp] nr=%d(%s) x1=%#x x2=%#x x3=%#x%s'%(nr,SYSNAME.get(nr,'?'),r.x1,r.x2,r.x3,extra))
    r.x0=0
try:
    ql.hook_address(h_tp, base+0x146be0); print('hook tp_syscall_imp @', hex(base+0x146be0))
except Exception as e: print('hook tp fail', e)
# fake JavaVM: [HEAP+0x40000]=vtable ptr; vtable = stub ptrs
VT=HEAP+0x41000
ql.mem.write(HEAP+0x40000, ql.pack64(VT))
for i in range(0x40): ql.mem.write(VT+i*8, ql.pack64(STUB))  # 都指向 ret0 桩
JVM=HEAP+0x40000
# 增强: fake JNIEnv (env->functions 表全 -> 桩); GetEnv(vm,&env,ver) 回填 env
GETENV=STUB+0x100000
ql.mem.write(GETENV, b"\xc0\x03\x5f\xd6")
ql.mem.write(VT+6*8, ql.pack64(GETENV))
ENV=HEAP+0x42000; FUNCS=HEAP+0x43000
CLEAN=STUB+0x100008; ql.mem.write(CLEAN, b"\xc0\x03\x5f\xd6")
ql.mem.write(ENV, ql.pack64(FUNCS))
for i in range(0x100): ql.mem.write(FUNCS+i*8, ql.pack64(CLEAN))
def h_getenv(q):
    r=q.arch.regs
    try: q.mem.write(r.x1, ql.pack64(ENV))
    except: pass
    r.x0=0; r.pc=r.x30
ql.hook_address(h_getenv, GETENV)
# RegisterNatives(JNIEnv idx 215) 捕获: 读 libtprt 注册给 Java 的 native 方法
REGNAT=[]
RN=STUB+0x100010; ql.mem.write(RN, b"\xc0\x03\x5f\xd6")
def h_rn(q):
    r=q.arch.regs; methods=r.x2; cnt=r.x3
    for i in range(cnt if cnt<200 else 200):
        try:
            b=methods+i*24
            namep=struct.unpack('<Q', q.mem.read(b,8))[0]
            sigp =struct.unpack('<Q', q.mem.read(b+8,8))[0]
            fnp  =struct.unpack('<Q', q.mem.read(b+16,8))[0]
            name=q.mem.read(namep,64).split(b'\x00')[0].decode('latin1')
            sig =q.mem.read(sigp,160).split(b'\x00')[0].decode('latin1')
            REGNAT.append((name,sig,fnp)); print('  [RegisterNatives] %s %s @0x%x'%(name,sig,fnp))
        except Exception as e: print('   rn err', e)
    r.x0=0; r.pc=r.x30
ql.hook_address(h_rn, RN)
ql.mem.write(FUNCS+215*8, ql.pack64(RN))
# 跑 init_array (解密构造函数)
ia=elf.get_section_by_name('.init_array')
ctors=[]
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name=='.rela.dyn':
        for rel in sec.iter_relocations():
            if ia and ia['sh_addr']<=rel['r_offset']<ia['sh_addr']+ia['sh_size']:
                ctors.append(rel['r_addend'] if sec.is_RELA() else 0)
print('ctors:',[hex(c) for c in ctors])
for k in range(31):
    try: setattr(ql.arch.regs,f'x{k}',0)
    except: pass
ql.arch.regs.sp=STK+STKSZ-0x1000; ql.arch.regs.x30=SENT
for c in ctors:
    try:
        ql.arch.regs.x0=0
        ql.emu_start(base+c, SENT, timeout=3_000_000, count=2_000_000)
        print('  ctor 0x%x done'%c)
    except Exception as e:
        print('  ctor 0x%x end:'%c, type(e).__name__, str(e)[:60])
# 跑 JNI_OnLoad
jni=[s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='JNI_OnLoad'][0]
va=jni['st_value']
print(f"跑 JNI_OnLoad @0x{va:x} (fake Jvm={JVM:#x})")
r=ql.arch.regs
for k in range(31):
    try: setattr(r,f'x{k}',0)
    except: pass
r.x0=JVM; r.x1=0; r.sp=STK+STKSZ-0x1000; r.x30=SENT
try: ql.emu_start(base+va, SENT, timeout=5_000_000, count=2_000_000)
except Exception as e: print("JNI_OnLoad 结束:", type(e).__name__, str(e)[:80])
print("JNI_OnLoad ret w0 =", ql.arch.regs.w0, "  pc=", hex(ql.arch.regs.pc))
# 逐个跑注册的 native 方法 (榨干检测点)
print("\n--- 跑 %d 个注册 native 方法 ---"%len(REGNAT))
def allocstr(s):
    p=HEAP+0x500000+allocstr.n; b=s.encode()+b'\x00'
    ql.mem.write(p,b); allocstr.n+=len(b)+0x20; return p
allocstr.n=0
def run1(fnp, setup, tag):
    SYS.clear()
    for k in range(31):
        try: setattr(ql.arch.regs,f'x{k}',0)
        except: pass
    ql.arch.regs.sp=STK+STKSZ-0x1000; ql.arch.regs.x30=SENT
    setup(ql.arch.regs)
    try: ql.emu_start(fnp if fnp else 0, SENT, timeout=3_000_000, count=2_000_000)
    except Exception as e: print("      [%s] end %s %s"%(tag,type(e).__name__,str(e)[:40]))
    if SYS: print("      [%s] syscalls: %s"%(tag,{SYSNAME.get(k,k):v for k,v in SYS.items()}))
for name,sig,fnp in REGNAT:
    print("  >>> %s %s"%(name,sig))
    if name=='initialize':
        def st(r):
            r.x0=ENV; r.x1=0
            r.x2=allocstr("com.hottagames.yh.laohu")
            r.x3=allocstr("/data/data/com.hottagames.yh.laohu/files")
            r.x4=allocstr("/data/app/com.hottagames.yh.laohu-1/lib/arm64")
            r.x5=allocstr("/data/app/com.hottagames.yh.laohu-1/base.apk")
            r.x6=0
        run1(fnp, st, 'initialize')
    elif name=='ioctl':
        for cmd in (0,1,2,3,4):
            def st(r,c=cmd):
                r.x0=ENV; r.x1=0; r.x2=c; r.x3=allocstr("stop")
            run1(fnp, st, 'ioctl cmd=%d'%cmd)
    else:
        def st(r):
            r.x0=ENV; r.x1=0; r.x2=0
        run1(fnp, st, name)
print("\n命中统计:", HITS)

# dump 数据区: 对比磁盘, 提取(可能已解密的)可读串
print("\n--- dump 数据区找串 ---")
import re as _re
KW=['frida','xposed','ptrace','/proc','debug','root','emul','qemu','magisk','hook','inject','maps','status','getprop','/system','/data','/su','selinux','/dev']
for name in ['.rodata','.data','.data.rel.ro']:
    s=elf.get_section_by_name(name)
    if not s: continue
    try: mem=ql.mem.read(base+s['sh_addr'], s['sh_size'])
    except Exception as e: print('read',name,e); continue
    disk=raw[s['sh_offset']:s['sh_offset']+s['sh_size']]
    diff=sum(1 for i in range(min(len(mem),len(disk))) if mem[i]!=disk[i])
    dstrs=set(m.group().decode('latin1') for m in _re.finditer(rb'[\x20-\x7e]{6,}', disk))
    strs=[m.group().decode('latin1') for m in _re.finditer(rb'[\x20-\x7e]{6,}', mem)]
    print('%s sz=0x%x diff=%d 可读串=%d'%(name,len(mem),diff,len(strs)))
    new=[t for t in strs if t not in dstrs]
    print('  [新/解密串 %d]'%len(new))
    for t in new[:50]: print('   |', t[:90])
f.close()
