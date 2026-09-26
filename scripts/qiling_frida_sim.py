# -*- coding: utf-8 -*-
"""QL 模拟 Frida：正确重定位(RELR)+TLS+PLT桩 + 在 Frida 会钩的地址挂 hook + 跑构造器。
hook = SetKey(0xABFA760) / Decrypt(0xABFA8E0) / Encrypt(0xABFA9A8) / Oodle / PakIdx / SSL_write。
watch = crypto 注册用到的全局(0xe35c9c8 等)。"""
import sys, struct, time
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE

SO=r"D:\qwork\libUnreal.so"; ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB_BASE=0x50000000; HEAP_BASE=0x51000000; STACK_BASE=0x60000000; STACK_SIZE=0x100000; SENT=0x6f000000
A_SETKEY=0xABFA760; A_DEC=0xABFA8E0; A_ENC=0xABFA9A8; A_OODLE=0xB587284
A_PAKIDX=0x3ADA03C; A_SSLW=0xB8854EC
WATCH={0xe63d578:"Oodle_fn",0xe1ec250:"dec_fn",0xe35c9c8:"crypto_arr",0xe35c9d0:"crypto_cnt",0xe35c880:"flag",0x35c9c8:"_t"}

t0=time.time()
def log(*a):
    try: print(f"[{time.time()-t0:6.1f}s]",*a,flush=True)
    except: pass

ql=Qiling([SO], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
base=ql.loader.load_address
log(f"base={base:#x}")
ql.mem.map(STUB_BASE,0x100000); ql.mem.map(HEAP_BASE,0x2000000)
ql.mem.map(STACK_BASE,STACK_SIZE); ql.mem.map(SENT,0x1000)
# TLS 金丝雀
TLS=HEAP_BASE+0x1000000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
try:
    from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
    ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS); log("TPIDR_EL0 set")
except Exception as e: log("TLS 失败",e)

f=open(SO,"rb"); elf=ELFFile(f); raw=f.read()
segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
# ---- RELR 批处理 ----
DT={t.entry.d_tag:t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags()}
if 'DT_ANDROID_RELR' in DT:
    relr_off=DT['DT_ANDROID_RELR']; relr_sz=DT['DT_ANDROID_RELRSZ']
    entries=[struct.unpack_from("<Q",raw,relr_off+i*8)[0] for i in range(relr_sz//8)]
    locs=[]; where=0
    for e in entries:
        if e&1==0: where=e; locs.append(where); where+=8
        else:
            for i in range(63):
                if e&(2<<i): locs.append(where+i*8)
            where+=63*8
    log(f"RELR: {len(locs)} 条")
    for v,fs,off,fl in segs:
        if not (fl&2): continue
        buf=bytearray(ql.mem.read(base+v,fs)); ch=0
        for loc in locs:
            if v<=loc<v+fs:
                o=loc-v; val=struct.unpack_from("<Q",buf,o)[0]
                if val: struct.pack_into("<Q",buf,o,(base+val)&0xFFFFFFFFFFFFFFFF); ch+=1
        if ch: ql.mem.write(base+v,bytes(buf))
    log("RELR applied")
else: log("no DT_ANDROID_RELR")
# ---- .rela.plt 桩 ----
stub=STUB_BASE; nstub=0
for sec in elf.iter_sections():
    if isinstance(sec,RelocationSection) and sec.name=='.rela.plt':
        for rel in sec.iter_relocations():
            ql.mem.write(stub,b"\xc0\x03\x5f\xd6"); ql.mem.write(base+rel['r_offset'],ql.pack64(stub)); stub+=0x10; nstub+=1
log(f"plt stubs: {nstub}")
def ret0(q): q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
for a in range(STUB_BASE,STUB_BASE+nstub*0x10,0x10): ql.hook_address(ret0,a)

# ---- QL 模拟 Frida hook ----
HIT={"SetKey":0,"Dec":0,"Enc":0,"Oodle":0,"PakIdx":0,"SSL":0}
def h_setkey(q):
    HIT["SetKey"]+=1; r=q.arch.regs; t=r.x1
    try:
        ptr=q.unpack64(q.mem.read(t,8)); n=q.unpack32(q.mem.read(t+8,4))
        kb=q.mem.read(ptr,min(n,64)); log(f"*** SetKey! size={n} key={kb.hex()}")
    except Exception as e: log(f"    SetKey 读参失败 {e!r}")
    r.pc=r.x30
ql.hook_address(h_setkey, base+A_SETKEY)
def mk(nm,addr,dumpw=False):
    def cb(q):
        HIT[nm]+=1; r=q.arch.regs
        s=f"    [hit {nm}] x0={r.x0:#x} x1={r.x1:#x} x2={r.x2:#x} x3={r.x3:#x}"
        if dumpw:
            try: s+=f" data={q.mem.read(r.x2,min(r.x3,64)).hex()}"
            except: pass
        log(s)
    ql.hook_address(cb, base+addr)
mk("Dec",A_DEC); mk("Enc",A_ENC); mk("Oodle",A_OODLE); mk("PakIdx",A_PAKIDX); mk("SSL",A_SSLW,True)

def snap():
    d={}
    for va,nm in WATCH.items():
        try: d[nm]=ql.unpack64(ql.mem.read(base+va,8))
        except: d[nm]=None
    return d

sec=[s for s in elf.iter_sections() if s.name=='.init_array']
n=sec[0]['sh_size']//8; iva=sec[0]['sh_addr']
log(f".init_array {n} entries")
prev=snap(); log("初始 watch:",{k:(hex(v) if v else v) for k,v in prev.items()})
ok=bad=0; budget=time.time()+1800
for i in range(n):
    if time.time()>budget: log("超预算, 停"); break
    entry=ql.unpack64(ql.mem.read(base+iva+i*8,8))
    if not entry: continue
    r=ql.arch.regs
    for k in range(31):
        try: setattr(r,f'x{k}',0)
        except: pass
    r.sp=STACK_BASE+STACK_SIZE-0x1000; r.x30=SENT
    try:
        ql.emu_start(entry, SENT, timeout=2_000_000, count=300000); ok+=1
    except Exception as e:
        bad+=1
        if bad<=3: log(f"   ctor#{i}@{entry:#x} {type(e).__name__}:{str(e)[:60]}")
    cur=snap()
    ch=[f"{k}:{prev[k] and hex(prev[k])}->{cur[k] and hex(cur[k])}" for k in cur if cur.get(k)!=prev.get(k)]
    if ch: log(f"ctor#{i}@{entry:#x} 改变: "+"; ".join(ch)); prev=cur
log(f"构造器 ok={ok} bad={bad}")
log("hit 统计:",HIT)
log("最终 watch:",{k:(hex(v) if v else v) for k,v in snap().items()})
log("DONE")
