# -*- coding: utf-8 -*-
"""QL 模拟 libthemis: 钩 prctl PLT 桩, 跑 init_array + 直接调反调试函数, 看谁触发。"""
import sys, struct, time
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
SO=r"D:\qwork\libthemis.so"
ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB=0x50000000; HEAP=0x51000000; STK=0x60000000; STKSZ=0x100000; SENT=0x6f000000
PRCTL_STUB=0xC8A60  # libthemis prctl PLT 桩
t0=time.time()
def log(*a): print(f"[{time.time()-t0:5.1f}s]",*a,flush=True)

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
log(f"base={base:#x}")
ql.mem.map(STUB,0x100000); ql.mem.map(HEAP,0x1000000); ql.mem.map(STK,STKSZ); ql.mem.map(SENT,0x1000)
TLS=HEAP+0x800000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
try:
    from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
    ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
except Exception as e: log("TLS",e)
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
# RELR
try:
    DT={t.entry.d_tag:t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags()}
    if 'DT_ANDROID_RELR' in DT:
        ro=DT['DT_ANDROID_RELR']; rs=DT['DT_ANDROID_RELRSZ']
        ents=[struct.unpack_from("<Q",raw,ro+i*8)[0] for i in range(rs//8)]
        locs=[]; where=0
        for e in ents:
            if e&1==0: where=e; locs.append(where); where+=8
            else:
                for i in range(63):
                    if e&(2<<i): locs.append(where+i*8)
                where+=63*8
        for v,fsz,o,fl in segs:
            if not (fl&2): continue
            buf=bytearray(ql.mem.read(base+v,fsz))
            for loc in locs:
                if v<=loc<v+fsz:
                    oo=loc-v; val=struct.unpack_from("<Q",buf,oo)[0]
                    if val: struct.pack_into("<Q",buf,oo,(base+val)&0xFFFFFFFFFFFFFFFF)
            ql.mem.write(base+v,bytes(buf))
        log(f"RELR {len(locs)}")
except Exception as e: log("RELR err",e)
# rela.plt 桩
nstub=0
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name=='.rela.plt':
        for rel in sec.iter_relocations():
            ql.mem.write(base+rel['r_offset'], ql.pack64(STUB+nstub*0x10)); ql.mem.write(STUB+nstub*0x10, b"\xc0\x03\x5f\xd6"); nstub+=1
log(f"plt stubs {nstub}")
def ret0(q): q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
for a in range(STUB,STUB+nstub*0x10,0x10): ql.hook_address(ret0,a)

# 钩 prctl PLT 桩
HITS=[]
def h_prctl(q):
    r=q.arch.regs; HITS.append(r.x0)
    log(f"  *** prctl 触发! w0={r.x0} (x1={r.x1:#x})")
    r.x0=0; r.pc=r.x30
ql.hook_address(h_prctl, base+PRCTL_STUB)

# init_array
sec=[s for s in elf.iter_sections() if s.name=='.init_array']
if sec:
    n=sec[0]['sh_size']//8; iva=sec[0]['sh_addr']
    log(f".init_array {n}")
    ok=bad=0
    for i in range(n):
        e=ql.unpack64(ql.mem.read(base+iva+i*8,8))
        if not e: continue
        r=ql.arch.regs
        for k in range(31):
            try: setattr(r,f'x{k}',0)
            except: pass
        r.sp=STK+STKSZ-0x1000; r.x30=SENT
        try: ql.emu_start(e,SENT,timeout=1_000_000,count=200000); ok+=1
        except Exception: bad+=1
    log(f"init_array ok={ok} bad={bad}  prctl命中={len(HITS)}")
# JNI_OnLoad
jni=[s.name for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='JNI_OnLoad']
if jni:
    sym=[s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='JNI_OnLoad'][0]
    va=sym['st_value']
    log(f"调 JNI_OnLoad @0x{va:x}")
    r=ql.arch.regs
    for k in range(31):
        try: setattr(r,f'x{k}',0)
        except: pass
    r.sp=STK+STKSZ-0x1000; r.x30=SENT
    try: ql.emu_start(base+va,SENT,timeout=2_000_000,count=500000)
    except Exception as e: log("JNI_OnLoad",type(e).__name__,str(e)[:60])
log(f"总 prctl 命中: {HITS}  (21=PR_SET_DUMPABLE, 39=PR_SET_PTRACER)")

# 直接执行反调试代码块 (0x71ef8: mov w0,#21 .. bl prctl)
log("直接执行反调试块 @0x71ef8 ...")
r=ql.arch.regs
for k in range(31):
    try: setattr(r,f'x{k}',0)
    except: pass
r.sp=STK+STKSZ-0x1000; r.x30=SENT
try:
    ql.emu_start(base+0x71EF8, SENT, timeout=1_000_000, count=100000)
    log("块正常结束")
except Exception as e:
    log("块执行异常(预期, 后半段混淆跳转)", type(e).__name__, str(e)[:60])
log(f"最终 prctl 命中: {HITS}")
log("DONE")
