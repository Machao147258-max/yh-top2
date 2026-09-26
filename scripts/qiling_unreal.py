# -*- coding: utf-8 -*-
"""Qiling 跑 libUnreal.so：加载+重定位+hook(key/AES/Oodle/SSL/pak)+跑构造器。"""
import sys, time, traceback
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

SO     = r"D:\qwork\libUnreal.so"
ROOTFS = r"D:\qwork\rootfs\arm64_android"

STUB_BASE=0x50000000; STUB_STRIDE=0x40
HEAP_BASE=0x51000000
STACK_BASE=0x60000000; STACK_SIZE=0x100000
SENTINEL=0x6f000000

# IDA 偏移（.so 基址 0）
A_SETKEY=0xABFA760; A_DEC=0xABFA8E0; A_ENC=0xABFA9A8
A_OODLE=0xB587284; A_PAKIDX=0x3ADA03C
A_SSLW=0xB8854EC; A_SSLR=0xB885330

t0=time.time()
def log(*a): print(f"[{time.time()-t0:7.1f}s]", *a, flush=True)

ql = Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base = ql.loader.load_address
log(f"load_address = {base:#x}")
ql.mem.map(STUB_BASE, 0x80000)
ql.mem.map(HEAP_BASE, 0x800000)
ql.mem.map(STACK_BASE, STACK_SIZE)
ql.mem.map(SENTINEL, 0x1000)
heap_ptr = HEAP_BASE + 0x1000

# ---- 手动重定位 ----
f=open(SO,"rb"); elf=ELFFile(f); dynsym=elf.get_section_by_name('.dynsym')
R_ABS64,R_GLOB,R_JUMP,R_REL=257,1025,1026,1027
stub_by_name={}; idx=0; nrel=nstub=ndef=0
for sec in elf.iter_sections():
    if not isinstance(sec,RelocationSection): continue
    if sec.name not in ('.rela.dyn','.rela.plt','.rel.plt'): continue
    for rel in sec.iter_relocations():
        off=rel['r_offset']; typ=rel['r_info_type']; add=rel['r_addend'] if sec.is_RELA() else 0
        if typ==R_REL:
            ql.mem.write(base+off, ql.pack64(base+add)); nrel+=1; continue
        sym=dynsym.get_symbol(rel['r_info_sym'])
        if sym['st_shndx']=='SHN_UNDEF' and sym.name:
            if sym.name not in stub_by_name:
                stub=STUB_BASE+idx*STUB_STRIDE; idx+=1; stub_by_name[sym.name]=stub
                ql.mem.write(stub,b"\xc0\x03\x5f\xd6")  # ret
            val=stub_by_name[sym.name]; nstub+=1
        elif sym.name and sym['st_shndx']!='SHN_UNDEF':
            val=base+sym['st_value']+add; ndef+=1
        else:
            continue
        ql.mem.write(base+off, ql.pack64(val))
f.close()
log(f"reloc done: relative={nrel} defined={ndef} stubs={nstub}")

# ---- hooks ----
def hook_setkey(q):
    r=q.arch.regs; t=r.x1
    try:
        ptr=q.unpack64(q.mem.read(t,8)); n=q.unpack32(q.mem.read(t+8,4))
        kb=q.mem.read(ptr, min(n,64))
        log(f"*** SetKey! size={n} key={kb.hex()}")
    except Exception as e:
        log(f"    SetKey 读参失败 {e!r}")
    r.pc=r.x30
ql.hook_address(hook_setkey, base+A_SETKEY)

def mk(name, dump=True):
    def cb(q):
        r=q.arch.regs
        s=f"    [hit {name}] x0={r.x0:#x} x1={r.x1:#x} x2={r.x2:#x} x3={r.x3:#x}"
        if dump and name=='SSL_write':
            try: s+=f" data={q.mem.read(r.x2,min(r.x3,64)).hex()}"
            except: pass
        log(s)
    return cb
ql.hook_address(mk("Dec"), base+A_DEC)
ql.hook_address(mk("Enc"), base+A_ENC)
ql.hook_address(mk("Oodle"), base+A_OODLE)
ql.hook_address(mk("PakIdx"), base+A_PAKIDX)
ql.hook_address(mk("SSL_write"), base+A_SSLW)
ql.hook_address(mk("SSL_read",False), base+A_SSLR)

# ---- 跑构造器 (.init_array) ----
try:
    ia=elf.get_section_by_name('.init_array') if False else None
except: pass
# 从内存读 .init_array（已重定位）
with open(SO,"rb") as f2:
    e2=ELFFile(f2); sec=[s for s in e2.iter_sections() if s.name=='.init_array']
    if sec:
        s=sec[0]; va=s['sh_addr']; n=s['sh_size']//8
        log(f".init_array: {n} entries @ {va:#x}")
        ok=bad=0
        for i in range(n):
            entry=ql.unpack64(ql.mem.read(base+va+i*8,8))
            if not entry: continue
            r=ql.arch.regs
            for k in range(31):
                try: setattr(r,f'x{k}',0)
                except: pass
            r.sp=STACK_BASE+STACK_SIZE-0x1000; r.x30=SENTINEL
            try:
                ql.emu_start(entry, SENTINEL, timeout=3_000_000, count=200000)
                ok+=1
            except Exception as e:
                bad+=1
                if bad<=5: log(f"   ctor#{i} @0x{entry:x} 异常: {type(e).__name__}: {str(e)[:80]}")
        log(f"构造器: ok={ok} bad={bad}")
log("DONE")
