# -*- coding: utf-8 -*-
"""QL 模拟 Frida: libthemis 原版 vs patch版 —— 只看第一次到达 prctl 桩时的桩指令。"""
import sys, struct
sys.path.insert(0, r"D:\逆向工具\qiling\qiling-master")
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
import capstone
MD=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
ROOTFS=r"D:\qwork\rootfs\arm64_android"
STUB=0x50000000; HEAP=0x51000000; STK=0x60000000; STKSZ=0x100000; SENT=0x6f000000
PRCTL_STUB=0xC8A60; BLOCK=0x71EF8

def run(so, tag):
    print(f"\n========== {tag} ==========")
    ql=Qiling([so], rootfs=ROOTFS, verbose=QL_VERBOSE.DISABLED)
    base=ql.loader.load_address
    ql.mem.map(STUB,0x100000); ql.mem.map(HEAP,0x1000000); ql.mem.map(STK,STKSZ); ql.mem.map(SENT,0x1000)
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
    for a in range(STUB,STUB+n*0x10,0x10): ql.hook_address(ret0,a)
    # prctl 桩指令(从已加载内存读)
    stub_ins=[f"{i.mnemonic} {i.op_str}" for i in MD.disasm(ql.mem.read(base+PRCTL_STUB,8), PRCTL_STUB)]
    print("prctl桩前2指令:", " | ".join(stub_ins))
    stop={"done":False}
    def h_stub(q):
        if not stop["done"]:
            stop["done"]=True
            print(f"  >> 到达 prctl 桩 (option x0={q.arch.regs.x0}) → 该桩是: {'PATCHED(mov w0,#0;ret)' if stub_ins and 'mov' in stub_ins[0] else 'ORIGINAL(adrp/ldr/br → 真 prctl)'}")
        q.arch.regs.x0=0; q.arch.regs.pc=q.arch.regs.x30
    ql.hook_address(h_stub, base+PRCTL_STUB)
    r=ql.arch.regs
    for k in range(31):
        try: setattr(r,f'x{k}',0)
        except: pass
    r.sp=STK+STKSZ-0x1000; r.x30=SENT
    try: ql.emu_start(base+BLOCK, SENT, timeout=500_000, count=100000)
    except Exception as e: print("  块异常(混淆, 预期):", type(e).__name__)
    print("  是否到达过 prctl 桩:", stop["done"])
    f.close()

run(r"D:\qwork\libthemis.so","原版 libthemis")
run(r"D:\qwork\libthemis_patched.so","PATCH版 libthemis")
