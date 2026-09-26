# -*- coding: utf-8 -*-
"""Qiling: 加载 libUnreal + RELR + 桩 + TLS -> 跑 .init_array 构造器 -> 检查 crypto 对象 -> 调解密。"""
import sys, struct, time
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
from collections import defaultdict

SO=r"D:\qwork\libUnreal.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
PAK=r"C:\Users\20751\Desktop\异环\unpacked\io\pakchunk0-Android_ASTC.pak"
STUB_BASE=0x50000000; HEAP_BASE=0x51000000; STACK_BASE=0x60000000; STACK_SIZE=0x100000; SENT=0x6f000000
A_DECRYPT=0x3AC7CA8; A_SETKEY=0xABFA760
t0=time.time()
def log(*a): print(f"[{time.time()-t0:6.1f}s]",*a,flush=True)

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
log(f"base={base:#x}")
ql.mem.map(STUB_BASE,0x100000); ql.mem.map(HEAP_BASE,0x2000000)
ql.mem.map(STACK_BASE,STACK_SIZE); ql.mem.map(SENT,0x1000)
TLS=HEAP_BASE+0x1000000
ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)

f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
DT={t.entry.d_tag:t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags()}
# RELR 批处理
relr_off=DT['DT_ANDROID_RELR']; relr_sz=DT['DT_ANDROID_RELRSZ']
entries=[struct.unpack_from("<Q",raw,relr_off+i*8)[0] for i in range(relr_sz//8)]
locs=[]; where=0
for e in entries:
    if e&1==0: where=e; locs.append(where); where+=8
    else:
        for i in range(63):
            if e&(2<<i): locs.append(where+i*8)
        where+=63*8
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
for v,fs,off,fl in segs:
    if not (fl&2): continue
    buf=bytearray(ql.mem.read(base+v,fs)); ch=0
    for loc in locs:
        if v<=loc<v+fs:
            o=loc-v; val=struct.unpack_from("<Q",buf,o)[0]
            if val: struct.pack_into("<Q",buf,o,(base+val)&0xFFFFFFFFFFFFFFFF); ch+=1
    if ch: ql.mem.write(base+v,bytes(buf))
log(f"RELR 应用 ({len(locs)} 条)")
# PLT 桩
stub=STUB_BASE; nstub=0
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name=='.rela.plt':
        for rel in sec.iter_relocations():
            ql.mem.write(stub,b"\xc0\x03\x5f\xd6"); ql.mem.write(base+rel['r_offset'],ql.pack64(stub)); stub+=0x10; nstub+=1
def ret0(q): q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
for a in range(STUB_BASE,STUB_BASE+nstub*0x10,0x10): ql.hook_address(ret0,a)
log(f"PLT 桩 {nstub}")

def call(vaddr,args,insn=2000000,us=5_000_000):
    r=ql.arch.regs
    for i in range(31):
        try: setattr(r,f'x{i}',0)
        except: pass
    for i,a in enumerate(args[:8]): setattr(r,f'x{i}',a)
    r.sp=STACK_BASE+STACK_SIZE-0x1000; r.x30=SENT
    return ql.emu_start(base+vaddr, SENT, timeout=us, count=insn)

# 跑构造器
sec=[s for s in elf.iter_sections() if s.name=='.init_array']
n=sec[0]['sh_size']//8; iva=sec[0]['sh_addr']
log(f".init_array {n} 个")
ok=bad=0; budget=time.time()+1200  # 20 分钟
for i in range(n):
    if time.time()>budget: log("时间预算到,停"); break
    entry=ql.unpack64(ql.mem.read(base+iva+i*8,8))
    if not entry: continue
    r=ql.arch.regs
    for k in range(31):
        try: setattr(r,f'x{k}',0)
        except: pass
    r.sp=STACK_BASE+STACK_SIZE-0x1000; r.x30=SENT
    try:
        ql.emu_start(entry, SENT, timeout=300_000, count=100000); ok+=1
    except Exception: bad+=1
log(f"构造器 ok={ok} bad={bad}")
# 检查 crypto 对象 0xe35c9c8
cnt=ql.unpack32(ql.mem.read(base+0xe35c9d0,4)); obj=ql.unpack64(ql.mem.read(base+0xe35c9c8,8))
log(f"crypto 对象: ptr={obj:#x} count={cnt}")
# 读 pak 索引, 调 sub_3AC7CA8
d=open(PAK,"rb").read(); idx=d[0x2f41376:0x2f41376+0x11320]
buf=HEAP_BASE+0x200000; ql.mem.write(buf, idx)
log(f"索引 {len(idx)} 写入 {buf:#x}, 调 sub_3AC7CA8 ...")
try:
    call(A_DECRYPT,[buf,len(idx),0x6c65,0])
    log(f"返回 w0={ql.arch.regs.w0:#x}")
    import hashlib
    out=bytes(ql.mem.read(buf,len(idx)))
    log(f"SHA1(处理后)={hashlib.sha1(out).hexdigest()}")
    log(f"目标        =eda462f54e6b194fa3474b5791dfab404b95ca7b")
    log(f"前32字节: {out[:32].hex()}")
except Exception as e:
    log(f"解密异常: {type(e).__name__}: {str(e)[:120]} pc={ql.arch.regs.pc:#x}")
log("DONE")
