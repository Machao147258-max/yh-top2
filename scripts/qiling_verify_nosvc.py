# -*- coding: utf-8 -*-
"""QL 验证 svc patch: 原版 vs libthemis_nosvc.so, 跑 JNI入口 0x33440 的哨兵反调试。
   模拟"svc 后 x17 被干扰(调试器/信号)": 原版 -> 返回NULL(反调试); patch(无svc) -> 进真实代码。"""
import sys, struct
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB=0x50000000; HEAP=0x51000000; STK=0x60000000; STKSZ=0x100000; SENT=0x6f000000
JNI_ENTRY=0x33440; REAL=0x33490; NULLPATH=0x33488
CLOBBER=True   # 模拟 svc 后 x17 被扰动

def run(so, tag):
    print(f"\n========== {tag} ==========")
    ql=Qiling([so], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
    base=ql.loader.load_address
    ql.mem.map(STUB,0x300000); ql.mem.map(HEAP,0x1000000); ql.mem.map(STK,STKSZ); ql.mem.map(SENT,0x1000)
    TLS=HEAP+0x800000; ql.mem.write(TLS+0x28, ql.pack64(0x1122334455667788))
    from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
    ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    f=open(so,"rb"); elf=ELFFile(f); raw=f.read()
    segs=[(s['p_vaddr'],s['p_filesz'],s['p_offset'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
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
    except Exception as e: print("RELR",e)
    n=0
    for sec in elf.iter_sections():
        if isinstance(sec,RelocationSection) and sec.name=='.rela.plt':
            for rel in sec.iter_relocations():
                ql.mem.write(base+rel['r_offset'], ql.pack64(STUB+n*0x10)); ql.mem.write(STUB+n*0x10,b"\xc0\x03\x5f\xd6"); n+=1
    def ret0(q): q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
    for i in range(n): ql.hook_address(ret0, STUB+i*0x10)
    # 扫 svc
    txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
    sites=[]
    for off in range(0,len(td)-4,4):
        w=struct.unpack_from("<I",td,off)[0]
        if (w & 0xFFE0001F)==0xD4000001: sites.append(tb+off)
    print(f"svc#0 条数: {len(sites)}")
    state={"svc":0,"end":"?"}
    def mk_svc(a):
        def cb(q):
            r=q.arch.regs; state["svc"]+=1
            print(f"  [svc] @0x{a:x} x8={r.x8}  {'→ 模拟扰动 x17(调试器/信号)' if CLOBBER else ''}")
            if CLOBBER: r.x17=2          # 扰动哨兵
            r.x0=0; r.pc=a+4
        return cb
    for a in sites: ql.hook_address(mk_svc(a), base+a)
    def h_real(q): state["end"]="真实代码(哨兵通过)"; q.arch.regs.pc=SENT
    def h_null(q): state["end"]="返回NULL(反调试触发)"; q.arch.regs.pc=SENT
    ql.hook_address(h_real, base+REAL)
    ql.hook_address(h_null, base+NULLPATH)
    r=ql.arch.regs
    for k in range(31):
        try: setattr(r,f'x{k}',0)
        except: pass
    r.sp=STK+STKSZ-0x1000; r.x30=SENT
    try: ql.emu_start(base+JNI_ENTRY, SENT, timeout=3_000_000, count=500000)
    except Exception as e: state["end"]=state["end"] if state["end"]!="?" else f"异常:{type(e).__name__}"
    print(f"→ svc 命中 {state['svc']} 次; 结局: {state['end']}")
    f.close()
    return state

o=run(r"D:\qwork\libthemis.so","原版 libthemis (229 svc)")
p=run(r"D:\qwork\libthemis_nosvc.so","PATCH版 libthemis (svc→nop)")
print("\n================ 结论 ================")
print(f"原版:   svc命中={o['svc']}  结局={o['end']}")
print(f"PATCH:  svc命中={p['svc']}  结局={p['end']}")
if o['svc']>0 and p['svc']==0 and "真实代码" in p['end']:
    print(">>> ✅ 验证通过: patch 移除了直接系统调用, 哨兵反调试被中和(原版被扰动触发, patch版不受影响)")
