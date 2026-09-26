# -*- coding: utf-8 -*-
"""列 libthemis 自身 .text 的内联 svc#0, 回溯 x8(系统调用号)。"""
import capstone
from elftools.elf.elffile import ELFFile
p=r'D:\qwork\libthemis.so'
elf=ELFFile(open(p,'rb'))
sysnames={56:'openat',48:'faccessat',79:'newfstatat',78:'readlinkat',63:'read',64:'write',93:'exit',94:'exit_group',
 167:'prctl',117:'ptrace',129:'kill',131:'tgkill',172:'getpid',178:'gettid',29:'ioctl',98:'futex',222:'mmap',
 215:'munmap',226:'mprotect',96:'set_tid_address',99:'set_robust_list',261:'prlimit64',160:'uname',113:'clock_gettime',
 174:'?174',221:'execve',220:'clone',260:'wait4',214:'brk',169:'getppid',175:'?175',223:'madvise',134:'rt_sigaction',135:'rt_sigprocmask',278:'?278'}
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
for sec in elf.iter_sections():
    if sec.name!='.text': continue
    a=sec['sh_addr']; data=sec.data()
    ins=list(md.disasm(data,a))
    idx={x.address:i for i,x in enumerate(ins)}
    sites=[]
    for i,x in enumerate(ins):
        if x.mnemonic=='svc': sites.append(i)
    print('libthemis .text svc#0 共',len(sites),'条')
    for i in sites:
        # 回溯最多 8 条找 x8
        nr=None
        for j in range(i-1, max(-1,i-9), -1):
            y=ins[j]
            if y.mnemonic in ('mov','movz') and y.op_str.startswith('x8, #'):
                nr=int(y.op_str.split('#')[1],0) if not y.op_str.split('#')[1].startswith('0x') else int(y.op_str.split('#')[1],16); break
            if y.mnemonic=='movk' and y.op_str.startswith('x8'): break
        nm = sysnames.get(nr,'sys%s'%nr) if nr is not None else '?'
        print('  0x%x  x8=%s (%s)  ; %s'%(ins[i].address, nr, nm, ' | '.join('%s %s'%(z.mnemonic,z.op_str) for z in ins[max(0,i-3):i])))
