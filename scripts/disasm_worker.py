# -*- coding: utf-8 -*-
"""反汇编 libsecsdk worker 区 0xfcfc 附近 + 标出 JNI 表项访问(env->functions[idx])."""
import capstone
from elftools.elf.elffile import ELFFile
SO=r"D:\qwork\libsecsdk.so"
f=open(SO,"rb"); elf=ELFFile(f)
txt=elf.get_section_by_name('.text'); tb=txt['sh_addr']; td=txt.data()
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
JNI={6:'FindClass',15:'ExceptionOccurred',28:'NewObject',31:'GetObjectClass',33:'GetMethodID',
     94:'GetFieldID',113:'GetStaticMethodID',144:'GetStaticFieldID',
     167:'NewStringUTF',169:'GetStringUTFChars',171:'GetArrayLength',173:'GetObjectArrayElement',
     114:'CallStaticObjectMethod',34:'CallObjectMethod',141:'CallStaticVoidMethod',61:'CallVoidMethod',
     215:'RegisterNatives',228:'ExceptionCheck',232:'GetMethodName',145:'GetStaticObjectField'}
for start,ln in [(0xfcfc,0x120),(0xfd40,0x60),(0xf246,0xc0)]:
    print(f"\n=== 0x{start:x} ===")
    fo=start-tb
    for ins in md.disasm(td[fo:fo+ln], start):
        t=f"{ins.mnemonic} {ins.op_str}"
        # 标 JNI 表项 ldr xT,[xS,#imm]
        if ins.mnemonic=="ldr" and "#0x" in ins.op_str and "[" in ins.op_str:
            try:
                off=int(ins.op_str.split('#')[1].rstrip(']'),16)
                if off%8==0 and off>0 and off//8 in JNI: t+=f"   ; JNI->{JNI[off//8]}(idx{off//8})"
            except: pass
        if ins.mnemonic in ("bl","b"):
            try: t+=" ->0x%x"%int(ins.op_str.split('#')[1],16)
            except: pass
        print(f"0x{ins.address:x}: {t}")
f.close()
