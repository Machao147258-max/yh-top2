# -*- coding: utf-8 -*-
"""Qiling: 跑构造器, 逐个后快照关键全局, 找出注册 crypto/Oodle 的构造器。"""
import sys, struct, time
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
SO=r"D:\qwork\libUnreal.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB_BASE=0x50000000; HEAP_BASE=0x51000000; STACK_BASE=0x60000000; STACK_SIZE=0x100000; SENT=0x6f000000
WATCH={0xe63d578:"Oodle_fn", 0xe1ec250:"dec_fn", 0xe35c9c8:"crypto_arr", 0xe35c9d0:"crypto_cnt", 0xe35c880:"flag"}
t0=time.time()
def log(*a): print(f"[{time.time()-t0:6.1f}s]",*a,flush=True)

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
ql.mem.map(STUB_BASE,0x100000); ql.mem.map(HEAP_BASE,0x2000000)
ql.mem.map(STACK_BASE,STACK_SIZE); ql.mem.map(SENT,0x1000)
TLS=HEAP_BASE+0x1000000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
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
for s in elf.iter_segments():
    if s['p_type']!='PT_LOAD' or not (s['p_flags']&2): continue
    v,fs,off=s['p_vaddr'],s['p_filesz'],s['p_offset']
    buf=bytearray(ql.mem.read(base+v,fs)); ch=0
    for loc in locs:
        if v<=loc<v+fs:
            o=loc-v; val=struct.unpack_from("<Q",buf,o)[0]
            if val: struct.pack_into("<Q",buf,o,(base+val)&0xFFFFFFFFFFFFFFFF); ch+=1
    if ch: ql.mem.write(base+v,bytes(buf))
stub=STUB_BASE; nstub=0
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name=='.rela.plt':
        for rel in sec.iter_relocations():
            ql.mem.write(stub,b"\xc0\x03\x5f\xd6"); ql.mem.write(base+rel['r_offset'],ql.pack64(stub)); stub+=0x10; nstub+=1
def ret0(q): q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
for a in range(STUB_BASE,STUB_BASE+nstub*0x10,0x10): ql.hook_address(ret0,a)
def snap():
    d={}
    for va,nm in WATCH.items():
        try: d[nm]=ql.unpack64(ql.mem.read(base+va,8))
        except: d[nm]=None
    return d
sec=[s for s in elf.iter_sections() if s.name=='.init_array']
n=sec[0]['sh_size']//8; iva=sec[0]['sh_addr']
prev=snap(); log(f"初始: {prev}")
budget=time.time()+1500
for i in range(n):
    if time.time()>budget: break
    entry=ql.unpack64(ql.mem.read(base+iva+i*8,8))
    if not entry: continue
    r=ql.arch.regs
    for k in range(31):
        try: setattr(r,f'x{k}',0)
        except: pass
    r.sp=STACK_BASE+STACK_SIZE-0x1000; r.x30=SENT
    try: ql.emu_start(entry, SENT, timeout=300_000, count=100000)
    except Exception: pass
    cur=snap()
    ch=[f"{k}:{prev[k]:#x}->{cur[k]:#x}" for k in cur if cur.get(k)!=prev.get(k)]
    if ch: log(f"ctor#{i} @0x{entry:x} 改变: " + "; ".join(ch)); prev=cur
log(f"最终: {snap()}")
log("DONE")
