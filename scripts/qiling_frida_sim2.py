# -*- coding: utf-8 -*-
"""QL 模拟 Frida：正确环境 + hook + 直接调 key-provider(0x9a93d08) dump key，
再试注册(0x26a26e8) + 解密链(0x3AC7E14/0x3AC7CA8)。"""
import sys, struct, time
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE

SO=r"D:\qwork\libUnreal.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB_BASE=0x50000000; HEAP_BASE=0x51000000; STACK_BASE=0x60000000; STACK_SIZE=0x100000; SENT=0x6f000000
A_KEYPROV=0x9A93D08   # key-provider 回调(返回 32B key)
A_REG=0x26A26E8       # 注册函数
A_GETKEY=0x3AC7E14    # 取key(out32,guid)
A_PAKDEC=0x3AC7CA8    # pak索引解密
A_DECFN=0x264DA0C     # 解密蹦床
KS=0xE295CD8          # keystore 全局
t0=time.time()
def log(*a): print(f"[{time.time()-t0:6.1f}s]",*a,flush=True)

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
log(f"base={base:#x}")
ql.mem.map(STUB_BASE,0x100000); ql.mem.map(HEAP_BASE,0x2000000)
ql.mem.map(STACK_BASE,STACK_SIZE); ql.mem.map(SENT,0x1000)
TLS=HEAP_BASE+0x1000000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
try:
    from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
    ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS); log("TPIDR_EL0 ok")
except Exception as e: log("TLS err",e)

f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
# RELR
DT={t.entry.d_tag:t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags()}
relr_off=DT['DT_ANDROID_RELR']; relr_sz=DT['DT_ANDROID_RELRSZ']
entries=[struct.unpack_from("<Q",raw,relr_off+i*8)[0] for i in range(relr_sz//8)]
locs=[]; where=0
for e in entries:
    if e&1==0: where=e; locs.append(where); where+=8
    else:
        for i in range(63):
            if e&(2<<i): locs.append(where+i*8)
        where+=63*8
for v,fs,off,fl in segs:
    if not (fl&2): continue
    buf=bytearray(ql.mem.read(base+v,fs)); ch=0
    for loc in locs:
        if v<=loc<v+fs:
            o=loc-v; val=struct.unpack_from("<Q",buf,o)[0]
            if val: struct.pack_into("<Q",buf,o,(base+val)&0xFFFFFFFFFFFFFFFF); ch+=1
    if ch: ql.mem.write(base+v,bytes(buf))
log("RELR ok")
stub=STUB_BASE; nstub=0
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name=='.rela.plt':
        for rel in sec.iter_relocations():
            ql.mem.write(stub,b"\xc0\x03\x5f\xd6"); ql.mem.write(base+rel['r_offset'],ql.pack64(stub)); stub+=0x10; nstub+=1
log(f"stubs {nstub}")
def ret0(q): q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
for a in range(STUB_BASE,STUB_BASE+nstub*0x10,0x10): ql.hook_address(ret0,a)

# ---- QL hooks (模拟 Frida 打点) ----
def h_keyprov(q):
    log(f"  [FRIDA-SIM hit] key-provider 0x9A93D08  out={q.arch.regs.x0:#x}")
ql.hook_address(h_keyprov, base+A_KEYPROV)
def h_reg(q):
    log(f"  [FRIDA-SIM hit] registrar 0x26A26E8  x0={q.arch.regs.x0:#x}")
ql.hook_address(h_reg, base+A_REG)

def call(vaddr,args,us=20_000_000,insn=2_000_000):
    r=ql.arch.regs
    for i in range(31):
        try: setattr(r,f'x{i}',0)
        except: pass
    for i,a in enumerate(args[:8]): setattr(r,f'x{i}',a)
    r.sp=STACK_BASE+STACK_SIZE-0x1000; r.x30=SENT
    return ql.emu_start(base+vaddr, SENT, timeout=us, count=insn)

# ===== 1) 直接调 key-provider 回调, dump key =====
OUT=HEAP_BASE+0x30000; ql.mem.write(OUT, b"\x00"*32)
log("调 key-provider 0x9a93d08 ...")
try:
    call(A_KEYPROV,[OUT]); log(f"返回, pc={ql.arch.regs.pc:#x}")
    kb=bytes(ql.mem.read(OUT,32))
    log(f"*** key = {kb.hex()}")
except Exception as e: log(f"异常 {type(e).__name__}: {str(e)[:100]} pc={ql.arch.regs.pc:#x}")

# ===== 2) 试注册: 0x26a26e8(x0=0x9a93d08) =====
log("调注册函数 0x26a26e8(x0=key-provider) ...")
try:
    call(A_REG,[base+A_KEYPROV]); log(f"返回 pc={ql.arch.regs.pc:#x}")
    ks=ql.unpack64(ql.mem.read(base+KS,8)); log(f"keystore[0xe295cd8] = {ks:#x}")
except Exception as e: log(f"异常 {type(e).__name__}: {str(e)[:100]} pc={ql.arch.regs.pc:#x}")

# ===== 3) 取key: 0x3AC7E14(out32, guid) =====
GUID=HEAP_BASE+0x31000; ql.mem.write(GUID, b"\x00"*32)
OUT2=HEAP_BASE+0x32000; ql.mem.write(OUT2,b"\x00"*32)
log("调 sub_3AC7E14(out,guid) ...")
try:
    call(A_GETKEY,[OUT2,GUID]); log(f"返回 pc={ql.arch.regs.pc:#x} out={bytes(ql.mem.read(OUT2,32)).hex()}")
except Exception as e: log(f"异常 {type(e).__name__}: {str(e)[:100]} pc={ql.arch.regs.pc:#x}")
log("DONE")
