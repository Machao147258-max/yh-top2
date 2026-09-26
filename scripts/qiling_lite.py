# -*- coding: utf-8 -*-
"""轻量 Qiling: 加载 libUnreal + 打重定位(RELR批处理 + .rela.plt桩) -> 直接调 AES 类。
验证: SetKey(key16) + Encrypt(16B) 是否 == AES-128-ECB。"""
import sys, struct, time
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
from Crypto.Cipher import AES

SO=r"D:\qwork\libUnreal.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB_BASE=0x50000000; HEAP_BASE=0x51000000; STACK_BASE=0x60000000; STACK_SIZE=0x100000; SENT=0x6f000000
A_SETKEY=0xABFA760; A_ENC=0xABFA9A8; A_DEC=0xABFA8E0
t0=time.time()
def log(*a): print(f"[{time.time()-t0:6.1f}s]",*a,flush=True)

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
log(f"base={base:#x}")
ql.mem.map(STUB_BASE,0x80000); ql.mem.map(HEAP_BASE,0x1000000)
ql.mem.map(STACK_BASE,STACK_SIZE); ql.mem.map(SENT,0x1000)
# TLS 栈金丝雀: tpidr_el0 -> TLS 块, +0x28 放 canary
TLS=HEAP_BASE+0x80000
ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
try:
    from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
    ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    log("TPIDR_EL0 已设置")
except Exception as e:
    log(f"TPIDR_EL0 设置失败: {e!r}")

# 段映射 (va->文件偏移, 只读数据段)
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
segs=[]
for seg in elf.iter_segments():
    if seg['p_type']!='PT_LOAD': continue
    segs.append((seg['p_vaddr'], seg['p_filesz'], seg['p_offset'], seg['p_flags']))
def va2fo(va):
    for v,fs,off,fl in segs:
        if v<=va<v+fs: return off+(va-v)
    return None

# ---- RELR 批处理 ----
dyn=elf.get_section_by_name('.dynamic'); DT={t.entry.d_tag:t.entry.d_val for t in dyn.iter_tags()}
relr_off=DT['DT_ANDROID_RELR']; relr_sz=DT['DT_ANDROID_RELRSZ']
entries=[struct.unpack_from("<Q",raw,relr_off+i*8)[0] for i in range(relr_sz//8)]
locs=[]; where=0
for e in entries:
    if e&1==0: where=e; locs.append(where); where+=8
    else:
        for i in range(63):
            if e&(2<<i): locs.append(where+i*8)
        where+=63*8
log(f"RELR: {len(locs)} 条相对重定位")
# 按段批处理: 读内存 -> +base -> 写回
from collections import defaultdict
bysegs=defaultdict(list)
for loc in locs:
    bysegs[va2fo(loc)].append(loc) if False else None
# 直接对全 RW 段处理
for v,fs,off,fl in segs:
    if not (fl & 2): continue   # 只要可写段(.data.rel.ro/.got/.data)
    buf=bytearray(ql.mem.read(base+v, fs))
    changed=0
    for loc in locs:
        if v<=loc<v+fs:
            o=loc-v
            val=struct.unpack_from("<Q",buf,o)[0]
            struct.pack_into("<Q",buf,o,(base+val)&0xFFFFFFFFFFFFFFFF); changed+=1
    if changed: ql.mem.write(base+v, bytes(buf))
log(f"RELR 应用完成")

# ---- .rela.plt -> 桩 ----
stub=STUB_BASE; nstub=0
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name=='.rela.plt':
        for rel in sec.iter_relocations():
            ql.mem.write(stub, b"\xc0\x03\x5f\xd6")  # ret
            ql.mem.write(base+rel['r_offset'], ql.pack64(stub)); stub+=0x10; nstub+=1
log(f".rela.plt 桩: {nstub}")

# 默认桩返回0
def ret0(q): q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
for a in range(STUB_BASE, STUB_BASE+nstub*0x10, 0x10):
    ql.hook_address(ret0, a)

def call(vaddr, args, insn=500000, us=20_000_000):
    r=ql.arch.regs
    for i in range(31):
        try: setattr(r,f'x{i}',0)
        except: pass
    for i,a in enumerate(args[:8]): setattr(r,f'x{i}',a)
    r.sp=STACK_BASE+STACK_SIZE-0x1000; r.x30=SENT
    return ql.emu_start(base+vaddr, SENT, timeout=us, count=insn)

# ---- 验证 AES-128-ECB ----
THIS=HEAP_BASE+0x10000; TARR=HEAP_BASE+0x20000; KEYB=HEAP_BASE+0x21000; DATA=HEAP_BASE+0x22000
key=b"0123456789abcdef"; pt=b"HELLO_AES_128__!"  # 16B
ql.mem.write(KEYB, key); ql.mem.write(TARR, ql.pack64(KEYB)+ql.pack32(16)+ql.pack32(16))  # TArray{data@0,num@8,max@12}
ql.mem.write(DATA, pt)
ql.mem.write(THIS, b"\x00"*0x400)
log("调 SetKey ...")
try:
    call(A_SETKEY, [THIS, TARR, 0]); log(f"SetKey 返回 w0={ql.arch.regs.w0:#x}")
except Exception as e: log(f"SetKey 异常: {type(e).__name__}: {str(e)[:100]} pc={ql.arch.regs.pc:#x}")
OUTCNT=HEAP_BASE+0x23000; ql.mem.write(OUTCNT, ql.pack32(0))
ql.mem.write(DATA, pt)  # 复位明文
log("调 Encrypt ...")
try:
    call(A_ENC, [THIS, OUTCNT, DATA, 16, 0]); log(f"Encrypt 返回 w0={ql.arch.regs.w0:#x}")
except Exception as e: log(f"Encrypt 异常: {type(e).__name__}: {str(e)[:100]} pc={ql.arch.regs.pc:#x}")
got=bytes(ql.mem.read(DATA,16))
exp=AES.new(key, AES.MODE_ECB).encrypt(pt)
log(f"得到 : {got.hex()}")
log(f"期望 : {exp.hex()}   （pycryptodome AES-128-ECB）")
log(f"匹配 : {got==exp}")
