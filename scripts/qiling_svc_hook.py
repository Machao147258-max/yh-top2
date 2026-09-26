# -*- coding: utf-8 -*-
"""Qiling 内核边界仿真: 钩 libthemis 的每条 svc#0, 读 x8(系统调用号)+参数, 演示拦截直接系统调用。"""
import sys, struct
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
import capstone
MD=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
SO=r"D:\qwork\libthemis.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB=0x50000000; HEAP=0x51000000; STK=0x60000000; STKSZ=0x100000; SENT=0x6f000000
SYS={167:'prctl',117:'ptrace',129:'kill',131:'tgkill',93:'exit',94:'exit_group',172:'getpid',
     178:'gettid',56:'openat',48:'faccessat',79:'newfstatat',78:'readlinkat',63:'read',64:'write',
     226:'mprotect',222:'mmap',215:'munmap',98:'futex',221:'execve',96:'set_tid_address',
     99:'set_robust_list',261:'prlimit64',160:'uname',113:'clock_gettime',278:'getrandom',
     64:'write',67:'pread64',29:'ioctl',215:'munmap'}

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
print(f"base={base:#x}")
ql.mem.map(STUB,0x200000); ql.mem.map(HEAP,0x1000000); ql.mem.map(STK,STKSZ); ql.mem.map(SENT,0x1000)
TLS=HEAP+0x800000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
def v2f(a):
    for v,fs,o,fl in segs:
        if v<=a<v+fs: return o+(a-v)
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
# PLT 桩
n=0
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name=='.rela.plt':
        for rel in sec.iter_relocations():
            ql.mem.write(base+rel['r_offset'], ql.pack64(STUB+n*0x10)); ql.mem.write(STUB+n*0x10,b"\xc0\x03\x5f\xd6"); n+=1
def ret0(q): q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
for i in range(n): ql.hook_address(ret0, STUB+i*0x10)
print("PLT桩",n)

# ==== 扫内存里的 svc#0 并逐条挂钩(内核边界) ====
txt=elf.get_section_by_name('.text'); tbase=txt['sh_addr']; tdata=txt.data()
svc_sites=[]
for off in range(0,len(tdata)-4,4):
    w=struct.unpack_from("<I",tdata,off)[0]
    if (w & 0xFFE0001F)==0xD4000001: svc_sites.append(tbase+off)
print(f"svc#0 共 {len(svc_sites)} 条")
print("前5个site:", [hex(x) for x in svc_sites[:5]])
# 校验: 读内存确认是 svc
for a in svc_sites[:3]:
    print(f"  site 0x{a:x} 内存字节={ql.mem.read(base+a,4).hex()}")
HITS={}
def mk_svc(a):
    def cb(q):
        r=q.arch.regs; x8=r.x8
        nm=SYS.get(x8,f'sys{x8}')
        HITS[nm]=HITS.get(nm,0)+1
        if HITS[nm]<=4:
            print(f"  [内核] svc -> {nm}(#{x8}) x0={r.x0} x1={r.x1} x2={r.x2}  @0x{a:x}")
        r.x0=0          # 假成功
        r.pc=a+4        # 跳过 svc
    return cb
for a in svc_sites: ql.hook_address(mk_svc(a), base+a)

# 反汇编 0x33440(JNI入口) 附近 (用 section 偏移, 正确)
print("\n=== 0x33440 附近 (JNI入口) ===")
fo=0x33440-tbase
for ins in MD.disasm(tdata[fo:fo+0x70], 0x33440):
    t=f"{ins.mnemonic} {ins.op_str}"
    if ins.mnemonic=="svc": t+="   <<< svc"
    print(f"0x{ins.address:x}: {t}")

# 跑 JNI 入口 0x33440 (无参, 允许中途崩)
r=ql.arch.regs
for k in range(31):
    try: setattr(r,f'x{k}',0)
    except: pass
r.sp=STK+STKSZ-0x1000; r.x30=SENT
print("\n=== 执行 0x33440 (JNI入口) ===")
try: ql.emu_start(base+0x33440, SENT, timeout=3_000_000, count=500000)
except Exception as e: print("结束:", type(e).__name__, str(e)[:70])
print("svc 命中统计:", HITS)
f.close()
