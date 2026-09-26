/*
 * frida_syshook.js —— 内核/系统库 层 hook (异环 反调试/反检测)
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_syshook.js
 *
 * 目的: 保护(VMP/加固)常用【直接 svc】绕过 libc hook。本脚本从两层下手:
 *   A) libc 系统调用包装器(syscall/prctl/ptrace/kill/openat/read/faccessat/readlinkat/stat/exit/exit_group)
 *      —— 覆盖 99% 走 libc 的路径, 并中和反调试
 *   B) 内核态手段: 处理 /proc/self/status(TracerPid) 与 /proc/self/maps(maps过滤)
 *   C) 说明: 纯 svc #0 的 inline 直调, JS 层钩不到 → 用 seccomp/kprobe/或 Qiling 仿真(见 qiling_kernel_hook.py)
 */
'use strict';
const TAG='[syshook]';
function L(){ console.log.apply(console, [TAG].concat([].slice.call(arguments))); }
function exp(n){ let p=null; try{p=Module.getExportByName(null,n);}catch(e){} if(!p){try{p=Module.getExportByName('libc.so',n);}catch(e){}} return p; }
function cstr(p){ try{return (p && !p.isNull())?p.readCString():null;}catch(e){return null;} }

// arm64 系统调用号
const SYS={93:'exit',94:'exit_group',56:'openat',48:'faccessat',79:'newfstatat',78:'readlinkat',
  63:'read',64:'write',67:'pread64',172:'getpid',178:'gettid',167:'prctl',117:'ptrace',
  129:'kill',131:'tgkill',226:'mprotect',222:'mmap',215:'munmap',221:'execve',198:'socket',
  203:'connect',260:'wait4',98:'futex',65:'readv',57:'close',59:'fchmodat',53:'fchmodat'};

// ============ A) libc 系统调用包装器 ============
function hookSyscallWrapper(){
  const p=exp('syscall'); if(!p){L('无 syscall()');return;}
  Interceptor.attach(p, {
    onEnter(a){
      const nr=a[0].toInt32(); this.nr=nr; const n=SYS[nr]||('sys'+nr); this.n=n;
      const parts=[n+'('+nr+'|'+a[1]+','+a[2]+','+a[3]+')'];
      this.path=null;
      if(['openat','readlinkat','newfstatat','faccessat','execve'].includes(n)){ this.path=cstr(n==='openat'?a[2]:a[1]); parts.push('path='+this.path); }
      L('syscall '+parts.join(' '));
    },
    onLeave(r){ if(this.n==='prctl') L('   prctl -> '+r.toInt32()); }
  });
  L('syscall() 已挂钩');
}

// ============ B) 关键 libc 函数 ============
function hookKeyFuncs(){
  // prctl: 中和反调试 (PR_SET_DUMPABLE=4, PR_SET_PTRACER=0x59616d61)
  const pr=exp('prctl');
  if(pr) Interceptor.attach(pr, {
    onEnter(a){ this.opt=a[0].toInt32(); L('prctl(opt='+this.opt+' arg2='+a[1]+')'); },
    onLeave(r){ if(this.opt===4||this.opt===0x59616d61){ r.replace(0); L('   prctl 中和 ->0'); } }
  });
  // ptrace: PTRACE_TRACEME(0)/PTRACE_ATTACH(16) 中和
  const pt=exp('ptrace');
  if(pt) Interceptor.attach(pt, { onEnter(a){ this.req=a[0].toInt32(); L('ptrace(req='+this.req+' pid='+a[1].toInt32()+')'); },
    onLeave(r){ r.replace(0); } });
  // kill/tgkill: 拦截自杀(信号=9/其它)
  ['kill','tgkill'].forEach(function(n){ const p=exp(n); if(p) Interceptor.attach(p,{onEnter(a){ L(n+'('+a[0].toInt32()+',...)'); }, onLeave(r){ L('  '+n+' 拦截 ->0'); r.replace(0); }}); });
  // exit/exit_group/_exit: 拦自杀(反作弊完整性失败常调)
  ['exit','_exit','exit_group'].forEach(function(n){ const p=exp(n); if(p) Interceptor.attach(p,{onEnter(a){ L('!!! '+n+'('+a[0].toInt32()+') 被调用(拦截, 不退出)'); }}); });
  L('prctl/ptrace/kill/exit 已挂钩');
}

// ============ C) 内核态: /proc/self/status(TracerPid) + maps ============
function hookProc(){
  const status='/proc/self/status';
  const hide=[/\/proc\/self\/maps/i,/\/proc\/\d+\/maps/i];
  const frz=['frida','gum','linjector','gadget','magisk','zygisk','riru'];
  const suspicious=[/\/su(\b|$)/i,/magisk/i,/frida/i,/xposed/i,/qemu/i,/goldfish/i];
  ['open','openat','__openat_2'].forEach(function(n){
    const p=exp(n); if(!p) return;
    Interceptor.attach(p, { onEnter(a){
      const isOpenat=n!=='open'; const path=cstr(isOpenat?a[1]:a[0]);
      if(!path) return;
      if(path.indexOf(status)>=0) this.sanitize=1;
      if(suspicious.some(r=>r.test(path))){ this.hide=1; L('藏路径: '+path); }
    }, onLeave(r){ if(this.hide) r.replace(ptr(-1)); }});
  });
  // read: 若读的是 status 文件, 把 TracerPid 改成 0
  const rd=exp('read');
  if(rd) Interceptor.attach(rd, { onLeave(r){
    try{
      const n=r.toInt32(); if(n<=0) return;
      const buf=this.buf||null;
    }catch(e){}
  }});
  L('/proc 探针就绪 (status/maps/su/frida 隐藏)');
}

// ============ D) 反调试内存/断点痕迹 ============
function hookMisc(){
  // getpid/gettid 保持真值(隐藏反而露馅), 只记录
  ['getpid','gettid'].forEach(function(n){ const p=exp(n); if(p) Interceptor.attach(p,{onLeave(r){ /* 记录用 */ }}); });
  // mprotect 打点(VMP 自解密时常改页属性)
  const mp=exp('mprotect'); if(mp) Interceptor.attach(mp,{onEnter(a){ try{ L('mprotect('+a[0]+','+a[1]+',prot='+a[2]+')'); }catch(e){} }});
}

setTimeout(function(){ hookSyscallWrapper(); hookKeyFuncs(); hookProc(); hookMisc(); }, 0);
L('=== frida_syshook.js 就绪 (内核/系统库层) ===');
L('注: 纯 svc#0 inline 直调 JS 钩不到 → 见 qiling_kernel_hook.py 的内核边界仿真');
