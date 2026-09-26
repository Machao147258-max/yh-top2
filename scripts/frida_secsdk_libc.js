/*
 * frida_secsdk_libc.js —— 针对 libsecsdk(网易易盾 DEX-VMP) 的 **libc 层** hook
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_secsdk_libc.js
 *
 * 依据: libsecsdk 有 **0 条 svc**(不走直接系统调用) → 全走 libc → **libc 层就是它的软肋**。
 * 本脚本只钩 libsecsdk 实际导入的 libc 函数, 覆盖其反外挂的每一类探针。
 *
 * libsecsdk 导入(libc 侧): dl_iterate_phdr, access, fopen, stat, fstat, exit, abort, __assert2,
 *   mmap, munmap, uncompress, puts, fprintf, fwrite, vsnprintf, sprintf, __sF, strstr, strcmp,
 *   strncpy, getcwd, mkdir, utime, pthread_*, malloc/free 等
 */
'use strict';
const TAG='[secsdk-libc]';
function L(){ console.log.apply(console, [TAG].concat([].slice.call(arguments))); }
function exp(n){ let p=null; try{p=Module.getExportByName(null,n);}catch(e){} if(!p){try{p=Module.getExportByName('libc.so',n);}catch(e){}} return p; }
function cstr(p){ try{return (p && !p.isNull())?p.readCString():null;}catch(e){return null;} }

// ===== 1) 反注入: dl_iterate_phdr 隐藏 frida/注入模块 =====
function hookPhdr(){
  const p=exp('dl_iterate_phdr'); if(!p){L('无 dl_iterate_phdr');return;}
  const RE=/(frida|gum|linjector|gadget|magisk|zygisk|riru|re\.frida|libsubstrate|edxp|xposed)/i;
  const orig=new NativeFunction(p,'int',['pointer','pointer']);
  Interceptor.replace(p, new NativeCallback(function(cbPtr,data){
    const real=new NativeFunction(cbPtr,'int',['pointer','size_t','pointer']);
    const cb=new NativeCallback(function(info,size,d){
      try{ const np=info.add(8).readPointer(); const nm=np.isNull()?null:np.readCString();
        if(nm && RE.test(nm)){ L('隐藏模块: '+nm); return 0; } }catch(e){}
      return real(info,size,d);
    },'int',['pointer','size_t','pointer']);
    return orig(cb,data);
  },'int',['pointer','pointer']));
  L('dl_iterate_phdr 反注入已挂钩');
}

// ===== 2) 文件探针: su/magisk/frida/调试 → 隐藏 =====
function hookFS(){
  const hide=[/\/su(\b|$)/i,/magisk/i,/frida/i,/xposed/i,/qemu/i,/goldfish/i,/genymotion/i,
              /\/proc\/self\/(status|maps|cmdline|task)/i, /tracerp/i, /\/data\/local\/tmp\/frida/i];
  const probe=[/\/proc\//i,/\/system\//i,/\/su/i,/magisk/i,/frida/i,/superuser/i,/busybox/i,/\/sbin/i];
  ['access','faccessat'].forEach(function(n){
    const p=exp(n); if(!p) return;
    Interceptor.attach(p,{ onEnter(a){ const path=cstr(n==='access'?a[0]:a[1]); if(!path) return;
      if(hide.some(r=>r.test(path))){ this.h=path; } else if(probe.some(r=>r.test(path))){ L('探测 '+n+' '+path); } },
      onLeave(r){ if(this.h){ L('藏 '+n+' '+this.h+' ->-1'); r.replace(-1); } }});
  });
  ['fopen','stat','fstat','__xstat','openat'].forEach(function(n){
    const p=exp(n); if(!p) return;
    Interceptor.attach(p,{ onEnter(a){ const path=cstr(n==='fopen'||n==='stat'?a[0]:(n==='openat'?a[1]:a[0]));
      if(path && hide.some(r=>r.test(path))){ this.h=path; } } , onLeave(r){ if(this.h){ L('藏 '+n+' '+this.h); r.replace(ptr(-1)); } }});
  });
  L('文件探针(su/magisk/frida/status) 已挂钩');
}

// ===== 3) 自杀: exit/abort/__assert2 → 阻断 =====
function hookKill(){
  ['exit','_exit'].forEach(function(n){ const p=exp(n); if(p) Interceptor.replace(p, new NativeCallback(function(c){ L('拦截 '+n+'('+c+')'); },'void',['int'])); });
  const ab=exp('abort'); if(ab) Interceptor.replace(ab, new NativeCallback(function(){ L('拦截 abort'); },'void',[]));
  const as=exp('__assert2'); if(as) Interceptor.attach(as,{onEnter(a){ const f=cstr(a[1]); L('__assert2 触发: '+f+':'+a[2].toInt32()+' '+(cstr(a[3])||'')); return; }});
  L('exit/abort/__assert2 已挂钩');
}

// ===== 4) 载荷: uncompress → dump DEX =====
function hookUncompress(){
  const p=exp('uncompress'); if(!p){L('无 uncompress');return;}
  Interceptor.attach(p,{ onEnter(a){ this.dst=a[0]; this.dl=a[1]; this.src=a[2]; this.sl=a[3].toInt32(); },
    onLeave(r){ if(r.toInt32()!==0) return;
      try{ const n=this.dl.readU32(); const bytes=this.dst.readByteArray(n);
        const h=new Uint8Array(bytes.slice(0,4)); const dex=h[0]===0x64&&h[1]===0x65&&h[2]===0x78;
        L('uncompress 输出 '+n+'字节 DEX='+dex);
        const f='/data/local/tmp/secsdk_payload'+(dex?'.dex':'.bin');
        const F=new File(f,'wb'); F.write(bytes); F.flush(); F.close(); L('落盘 '+f);
      }catch(e){ L('dump 失败',e); } }});
  L('uncompress 载荷抓取已挂钩');
}

// ===== 5) 输出捕获: 读 libsecsdk 自己打的日志 =====
function hookOutput(){
  const o=exp('puts'); if(o) Interceptor.attach(o,{onEnter(a){ const s=cstr(a[0]); if(s) L('[puts] '+s); }});
  const fp=exp('fprintf'); if(fp) Interceptor.attach(fp,{onEnter(a){ try{ const fmt=cstr(a[1]); if(fmt) L('[fprintf] '+fmt); }catch(e){} }});
  const fw=exp('fwrite'); if(fw) Interceptor.attach(fw,{onEnter(a){ try{ const n=a[2].toInt32(),sz=a[3].toInt32(); if(n*sz>0&&n<64) L('[fwrite] '+a[0].readUtf8String(n*sz)); }catch(e){} }});
  const sp=exp('sprintf'); if(sp) Interceptor.attach(sp,{onEnter(a){ try{ const fmt=cstr(a[1]); if(fmt) L('[sprintf] '+fmt); }catch(e){} }});
  L('输出捕获(puts/fprintf/fwrite/sprintf) 已挂钩');
}

// ===== 6) 字符串比较: strstr/strcmp (看它比对啥) =====
function hookStr(){
  const ss=exp('strstr'); if(ss) Interceptor.attach(ss,{onEnter(a){ try{ const h=cstr(a[0]); const n=cstr(a[1]); if(n&&n.length>2) L('strstr(hay="'+String(h).slice(0,40)+'", needle="'+n+'")'); }catch(e){} }});
  const sc=exp('strcmp'); if(sc) Interceptor.attach(sc,{ onLeave(r){ if(r.toInt32()===0) {} } });
  L('strstr/strcmp 已挂钩');
}

// ===== 7) 内存: mmap/munmap (VMP 自解密常改页) =====
function hookMem(){
  const mm=exp('mmap'); if(mm) Interceptor.attach(mm,{onEnter(a){ try{ if(a[3].toInt32()&7) L('mmap len='+a[1]+' prot='+a[3]+' flags='+a[4]); }catch(e){} }});
  const mu=exp('munmap'); if(mu) Interceptor.attach(mu,{ onEnter(a){ L('munmap '+a[0]+' len='+a[1]); }});
  L('mmap/munmap 已挂钩');
}

setTimeout(function(){ hookPhdr(); hookFS(); hookKill(); hookUncompress(); hookOutput(); hookStr(); hookMem(); }, 0);
['libsecsdk.so'].forEach(function(m){ var iv=setInterval(function(){ if(Process.findModuleByName(m)){ clearInterval(iv); L(m+' 已加载'); } },200); });
L('=== frida_secsdk_libc.js 就绪 (libsecsdk 的 libc 层) ===');
