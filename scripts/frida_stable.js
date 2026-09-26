/*
 * 异环 让 Frida "稳" 的综合脚本 (native + java 全层)
 * 依据: reports/66/67/68/69 —— 图灵盾(读 /proc/self/{status,maps}) / dfga(反Xposed) /
 *       Alipay(root/模拟器) / Bugly / 自研 —— 全在 JAVA 层; 原生检测走 libc(dl_iterate_phdr/open)。
 *
 * 启动(决定成败, 强烈建议):
 *   -f(spawn) 尽早注入, 且用"无 frida 字样"的 gadget/server:
 *     frida -U -f com.hottagames.yh.laohu -l frida_stable.js --no-pause
 *   或把 libfrida-gadget.so 改名(如 libyhn.so)塞进 APK, 监听模式启动。
 *   若不加 --no-pause / 用 attach, 冷启动瞬间的检测会先跑 → 可能已上报。
 */
'use strict';
const TAG = '[yh-stable]';
function L(){ console.log.apply(console, [TAG].concat([].slice.call(arguments))); }

/* ===================== 0. 常量 ===================== */
const HIDE_STR = ['frida','gum-js','gum-js-loop','gmain','gdbus','linjector','frida-agent',
                  'frida-server','re.frida','/data/local/tmp/re.','/data/local/tmp/frida','gadget'];
const BLOCK_PATH = /(\/su(\b|$)|(^|\/)su$|magisk|supersu|superuser|\/system\/.*\/su|\/sbin\/su|\/data\/local\/.*su|frida|gum-js|linjector|\/dev\/qemu_pipe|\/dev\/socket\/qemud|\/sys\/qemu_trace|qemu-props|goldfish|ranchu|libc_malloc_debug_qemu)/i;
const PROP_FAKE = { 'ro.kernel.qemu':'0','ro.debuggable':'0','ro.secure':'1','ro.build.type':'user',
                    'ro.boot.verifiedbootstate':'green','ro.boot.flash.locked':'1','ro.secureboot.lockstate':'locked',
                    'init.svc.adbd':'stopped','ro.adb.secure':'1' };

/* ===================== 1. 原生层 ===================== */
function exp(n){ let p=null; try{p=Module.getExportByName(null,n);}catch(e){} if(!p){try{p=Module.getExportByName('libc.so',n);}catch(e){}} return p; }
function cstr(p){ try{ return (p && !p.isNull())?p.readCString():null; }catch(e){ return null; } }

// 用 memfd/tmpfile 生成"洗过"的副本, 返回 fd; 失败返回 -1
function makeCleanFd(origPath, filterFn){
  let fd=-1;
  const memfd=exp('memfd_create');
  if(memfd){ try{ fd=new NativeFunction(memfd,'int',['pointer','uint'])(Memory.allocUtf8String('x'),0); }catch(e){} }
  if(fd<0){ try{ fd=new NativeFunction(exp('open'),'int',['pointer','int','int'])(Memory.allocUtf8String('/data/local/tmp/.yh'),2|64|512,0o600); }catch(e){ return -1; } }
  if(fd<0) return -1;
  // 读原始文件
  let txt='';
  try{
    const of=new NativeFunction(exp('open'),'int',['pointer','int','int'])(Memory.allocUtf8String(origPath),0,0); // O_RDONLY
    if(of>=0){
      const buf=Memory.alloc(64*1024); const rd=new NativeFunction(exp('read'),'long',['int','pointer','ulong']);
      const fs=new NativeFunction(exp('lseek'),'long',['int','int','int']);
      fs(of,0,2); const sz=Number(fs(of,0,0)); fs(of,0,0);
      let left=Math.min(sz,4*1024*1024);
      while(left>0){ const n=Number(rd(of,buf,Math.min(left,64*1024))); if(n<=0)break; txt+=buf.readUtf8String(n); left-=n; }
      new NativeFunction(exp('close'),'int',['int'])(of);
    }
  }catch(e){}
  const out = filterFn(txt);
  try{ new NativeFunction(exp('write'),'long',['int','pointer','ulong'])(fd, Memory.allocUtf8String(out), out.length); }catch(e){}
  new NativeFunction(exp('lseek'),'long',['int','int','int'])(fd,0,0);
  return fd;
}

// 过滤 /proc/self/maps: 去 frida/gum/注入相关行
function filterMaps(txt){
  return txt.split('\n').filter(l=>{ for(const s of HIDE_STR){ if(l.indexOf(s)>=0) return false; } return true; }).join('\n');
}
// 过滤 /proc/self/status: TracerPid=0, 及清可疑
function filterStatus(txt){
  if(!txt) return txt;
  return txt.replace(/TracerPid:.*\n/, 'TracerPid:\t0\n');
}

function hookOpenLike(fnName){
  const p=exp(fnName); if(!p) return;
  Interceptor.attach(p, {
    onEnter(a){
      this.fn=fnName; this.fail=false; this.repl=-1;
      const isAt = (fnName==='openat'||fnName==='__openat_2');
      const pathp = isAt ? a[1] : a[0];
      const path = cstr(pathp);
      this.path=path;
      if(!path) return;
      if(path==='/proc/self/maps' || path==='/proc/self/task/'+Process.getCurrentThreadId()+'/maps'){
        const fd=makeCleanFd(path, filterMaps);
        if(fd>=0){ this.repl=fd; L('maps -> clean fd',fd); }
      } else if(path==='/proc/self/status' || path==='/proc/self/task/'+Process.getCurrentThreadId()+'/status'){
        const fd=makeCleanFd(path, filterStatus);
        if(fd>=0){ this.repl=fd; L('status -> clean fd',fd); }
      } else if(BLOCK_PATH.test(path)){
        this.fail=true; L('block',fnName,path);
      }
    },
    onLeave(r){
      if(this.fail) r.replace(ptr(-2));            // fopen NULL / open -1
      else if(this.repl>=0 && this.fn==='fopen'){  // fopen: fd -> FILE*
        try{ r.replace(new NativeFunction(exp('fdopen'),'pointer',['int','pointer'])(this.repl, Memory.allocUtf8String('r'))); }catch(e){}
      } else if(this.repl>=0){ r.replace(ptr(this.repl)); }   // open/openat: 返回 fd
    }
  });
}
['fopen','fopen64','open','openat','__open_2','__openat_2'].forEach(hookOpenLike);

// 存在性/属性检查类: 命中 BLOCK_PATH 直接"不存在"
[['access','int'],['stat','int'],['lstat','int'],['__statfs','int'],['readlink','int'],['opendir','pointer'],['faccessat','int'],['__android_log_print','int']].forEach(function(it){
  const p=exp(it[0]); if(!p) return;
  Interceptor.attach(p,{ onEnter(a){ const isAt=(it[0]==='faccessat'); this.path=cstr(a[isAt?1:0]); this.bad=this.path&&BLOCK_PATH.test(this.path); if(this.bad)L(it[0],'-> '+(it[0]==='opendir'?'NULL':'-1'),this.path); },
    onLeave(r){ if(this.bad) r.replace( (it[0]==='opendir')?ptr(0):ptr(-1) ); } });
});

// __system_property_get: 假造属性
const spg=exp('__system_property_get');
if(spg) Interceptor.attach(spg,{ onEnter(a){ this.k=cstr(a[0]); this.out=a[1]; },
  onLeave(r){ if(this.k && PROP_FAKE[this.k]!==undefined){ const v=PROP_FAKE[this.k]; this.out.writeUtf8String(v); r.replace(v.length); } } });

// ptrace / prctl 反调试
const ptra=exp('ptrace');
if(ptra) Interceptor.attach(ptra,{ onLeave(r){ r.replace(ptr(0)); } });
const prct=exp('prctl');
if(prct) Interceptor.attach(prct,{ onEnter(a){ this.op=a[0].toInt32(); },
  onLeave(r){ if(this.op===4||this.op===21||this.op===3||this.op===0x59616d61||this.op===39) r.replace(ptr(0)); /* PR_SET_DUMPABLE=4/PR_GET_DUMPABLE=3/prctl(21)/PR_SET_PTRACER */ } });
// libthemis 反调试: 它的 .plt 桩 @base+0xc8a60 调 libc prctl(21) —— 直接兜底归零
(function(){ const th=Process.findModuleByName('libthemis.so'); if(th){ try{
  Interceptor.attach(th.base.add(0xc8a60),{ onLeave(r){ L('libthemis prctl stub -> 0'); r.replace(ptr(0)); } });
}catch(e){ L('libthemis stub hook 失败',e); } } })();

// popen: 图灵盾原生(libturingmfa)用 popen 跑 shell(getprop/ps/su/mount)——记录并拦敏感命令
const pop=exp('popen');
if(pop) Interceptor.attach(pop,{ onEnter(a){ this.cmd=cstr(a[0]); if(this.cmd)L('popen:',this.cmd);
    this.bad = !!(this.cmd && /(\bsu\b|magisk|getprop\s+ro\.|frida|\bps\b|\bmount\b|qemu|goldfish|\/proc\/)/i.test(this.cmd));
  }, onLeave(r){ if(this.bad) r.replace(ptr(0)); } });   // 敏感命令返回 NULL

// syscall(): 图灵盾/部分原生走 libc syscall()(非内联 svc) → 拦 prctl(167)/ptrace(117)/openat(56)
const sy=exp('syscall');
if(sy) Interceptor.attach(sy,{ onEnter(a){ this.nr=a[0].toInt32(); },
  onLeave(r){ if(this.nr===167||this.nr===117) r.replace(ptr(0)); } });

// --- 模块加载监听(库可能在脚本加载后才 dlopen) ---
function onModule(name, cb){
  var m=Process.findModuleByName(name);
  if(m){ try{ cb(m); }catch(e){} return; }
  var n=0, iv=setInterval(function(){ var x=Process.findModuleByName(name);
    if(x || ++n>1200){ clearInterval(iv); if(x){ try{ cb(x); }catch(e){} } } }, 100);
}
// libthemis 反调试: .plt 桩 @base+0xc8a60 调 libc prctl(21)
onModule('libthemis.so', function(th){ try{
  Interceptor.attach(th.base.add(0xc8a60),{ onLeave(r){ L('libthemis prctl stub -> 0'); r.replace(ptr(0)); } });
}catch(e){ L('libthemis stub hook 失败',e); } });
// libtprt(腾讯ACE): 用自带 tp_syscall_imp(raw svc, 绕过 libc) -> 直接 hook 该导出
//   实测它读 /proc/<pid>/cmdline 和 sdcard/sdk/enable.log (报告79)
onModule('libtprt.so', function(tp){
  var imp=null; try{ imp=Module.findExportByName('libtprt.so','tp_syscall_imp'); }catch(e){}
  if(!imp){ try{ imp=tp.base.add(0x146be0); }catch(e){} }
  if(imp) Interceptor.attach(imp,{
    onEnter(a){ this.nr=a[0].toInt32();
      try{ if(this.nr===56||this.nr===48){ this.path=a[2].readCString(); } }catch(e){}
    },
    onLeave(r){
      if(this.nr===117||this.nr===167) return r.replace(ptr(0));  // ptrace/prctl
      if((this.nr===56||this.nr===48) && this.path &&
         (/\/proc\/(self|\d+)\/(cmdline|status|maps|mountinfo|fd)|enable\.log|\/init\.vbox86\.rc|\/dev\/socket\/genyd|tencent\.tinput/i.test(this.path))){
        L('libtprt block',this.path); return r.replace(ptr(-1));  // 打开失败
      }    }
  });
  L('libtprt tp_syscall_imp hooked='+imp);
});
// libtprt(腾讯ACE) native 方法 = 检测漏斗(Java<->native): 记录命令与结果
onModule('libtprt.so', function(tp){
  var M={ 'initialize':0x25ae0, 'ioctl':0x136d7c, 'gp6ioctl':0x26058, 'gp7ioctl':0x25ea4 };
  Object.keys(M).forEach(function(nm){
    try{
      Interceptor.attach(tp.base.add(M[nm]), {
        onEnter(a){
          try{
            this.cmd = (nm==='ioctl') ? a[0].toInt32() : null;
            if(nm!=='initialize') this.s = a[(nm==='ioctl')?1:0].readCString();
          }catch(e){}
          L('libtprt.'+nm+'('+(this.cmd!==null?this.cmd:'')+(this.s?','+JSON.stringify(this.s):'')+')');
        },
        onLeave(r){ L('libtprt.'+nm+' -> '+r.toInt32()); }
      });
    }catch(e){}
  });
  L('libtprt 漏斗(ioctl/gp6ioctl/gp7ioctl/initialize) 已 hook');
});
// dl_iterate_phdr: 过滤注入模块
const dlip=exp('dl_iterate_phdr');if(dlip) Interceptor.attach(dlip,{
  onEnter(a){ this.cb=a[0]; this.ud=a[1];
    const cb=new NativeFunction(a[0],'int',['pointer','pointer','ulong']);
    const self=this;
    const cb2=new NativeCallback(function(info,size,data){
      try{ const name = info.add(8).readPointer(); const nm = name.isNull()? '':name.readCString();
        for(const s of HIDE_STR){ if(nm && nm.indexOf(s)>=0){ L('dl_iterate_phdr hide',nm); return 0; } } }catch(e){}
      try{ return cb(info,size,data); }catch(e){ return 0; }
    },'int',['pointer','pointer','ulong']);
    this.cb2=cb2; a[0]=cb2;
  }
});

/* ===================== 2. Java 层: 改检测方法返回 ===================== */
function U(n){ try{ return Java.use(n); }catch(e){ return null; } }
Java.perform(function(){
  // 反调试: Debug
  try{ const Db=Java.use('android.os.Debug'); Db.isDebuggerConnected.implementation=function(){return false;}; Db.waitingForDebugger.implementation=function(){return false;}; L('Debug hooked'); }catch(e){}
  // 图灵盾 Turingcam
  const tc=U('com.tencent.turingcam.oqKCa');
  if(tc){ try{ tc.b.overload('android.content.Context').implementation=function(){return 0;}; }catch(e){}
          try{ tc.a.overload('android.content.Context').implementation=function(){return 0;}; }catch(e){}
          try{ tc.f.overload().implementation=function(){return false;}; }catch(e){}
          ['i','j','l','m'].forEach(function(mn){ try{ tc[mn].overload('android.content.Context').implementation=function(){return false;}; }catch(e){} });
          L('turingcam hooked'); }
  // 图灵盾 Turingface
  const l32=U('com.tencent.turingface.sdk.mfa.L32b7');
  if(l32){ try{ l32.a.overload('android.content.Context').implementation=function(){return '';}; }catch(e){}
           try{ l32.a.overload('android.content.Context','java.lang.String').implementation=function(){return '';}; }catch(e){}
           try{ l32.a.overload().implementation=function(){return false;}; }catch(e){} }
  const rbd=U('com.tencent.turingface.sdk.mfa.rBDKv');
  if(rbd){ try{ rbd.a.overload('android.content.Context').implementation=function(){return null;}; }catch(e){} }
  // dfga 反 Xposed
  const dfga=U('com.wpsdk.dfga.sdk.utils.a.e');
  if(dfga){ try{ dfga.b.overload().implementation=function(){return false;}; L('dfga hooked'); }catch(e){} }
  // Alipay root/模拟器
  const a0b=U('com.alipay.sdk.m.a0.b'); if(a0b){ ['s','o','g','u','v'].forEach(function(mn){ try{ a0b[mn].overload().implementation=function(){return '';}; }catch(e){} }); }
  const a0e=U('com.alipay.sdk.m.a0.e'); if(a0e){ try{ a0e.c.overload().implementation=function(){return false;}; }catch(e){} try{ a0e.d.overload().implementation=function(){return false;}; }catch(e){} }
  const msb=U('com.alipay.sdk.m.s.b'); if(msb){ try{ msb.e.overload().implementation=function(){return false;}; }catch(e){} }
  // 自研
  const yhw=U('com.hottagames.yhwrapper.a'); if(yhw){ try{ yhw.b.overload('java.lang.String','java.lang.String').implementation=function(){return false;}; }catch(e){} }
  // Bugly
  const ab=U('com.tencent.bugly.idasc.proguard.ab'); if(ab){ ['o','p','q','r','s'].forEach(function(mn){ try{ ab[mn].overload().implementation=function(){return false;}; }catch(e){} }); }
  L('Java 层反检测已装');
});

/* ===================== 3. 自检 ===================== */
L('native hooks 已装; 自检:');
try{ L('  maps 含 frida?', require === undefined ? '?' : ''); }catch(e){}
L('done.');
