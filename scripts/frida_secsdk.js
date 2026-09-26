/*
 * 针对 libsecsdk.so 的 Frida 脚本 (异环 反作弊/完整性)
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_secsdk.js
 * 依据: reports/45 —— libsecsdk = 熟化VMP; QL 不可模拟; 只能真机 hook
 *
 * libsecsdk 的"需要啥"(导入): dl_iterate_phdr / exit / abort / access / open /
 *   fopen / stat / fstat / dlopen / dlsym / mmap / mprotect / uncompress
 *
 * 针对点:
 *  1) dl_iterate_phdr  -> 隐藏注入模块(frida/gum)
 *  2) exit/_exit/abort -> 阻止"校验失败自杀"(闪退源)
 *  3) 文件探针          -> 藏 su/magisk/frida/可疑路径
 *  4) dlopen/dlsym      -> 打点(看它运行时加载啥)
 *  5) Java System.loadLibrary("secsdk") -> 打点(定位加载时刻)
 */
'use strict';
const TAG='[secsdk]';
function L(){ console.log.apply(console, [TAG].concat([].slice.call(arguments))); }
function sym(s){ let p=null; try{p=Module.getExportByName(null,s);}catch(e){} if(!p){try{p=Module.getExportByName('libc.so',s);}catch(e){}} return p; }

// 把 rL 的 Object 参数解析成人话
function desc(o){
  if(o===null) return 'null';
  try{
    var cls=o.$className;
    if(cls==='java.lang.Class') return 'Class<'+Java.cast(o,Java.use('java.lang.Class')).getName()+'>';
    if(cls==='java.lang.String') return JSON.stringify(String(o).slice(0,80));
    if(cls==='java.lang.reflect.Method'){ var m=Java.cast(o,Java.use('java.lang.reflect.Method')); return 'Method{'+m.getDeclaringClass().getName()+'.'+m.getName()+'}'; }
    if(cls==='java.lang.reflect.Field'){ var f=Java.cast(o,Java.use('java.lang.reflect.Field')); return 'Field{'+f.getDeclaringClass().getName()+'.'+f.getName()+'}'; }
    if(cls && cls[0]==='[') return cls+'('+String(o).slice(0,60)+')';
    if(cls) return cls+'('+String(o).slice(0,50)+')';
    return String(o).slice(0,60);
  }catch(e){ return '(?)'; }
}

// ---------- 1) dl_iterate_phdr 隐藏注入模块 ----------
function hookDl(){
  const p=sym('dl_iterate_phdr'); if(!p){ L('无 dl_iterate_phdr'); return; }
  const orig=new NativeFunction(p,'int',['pointer','pointer']);
  Interceptor.replace(p, new NativeCallback(function(cbPtr,data){
    const realCb=new NativeFunction(cbPtr,'int',['pointer','size_t','pointer']);
    const ourCb=new NativeCallback(function(info,size,d){
      try{ const np=info.add(8).readPointer(); const nm=np.isNull()?null:np.readCString();
        if(nm && /(frida|gum|linjector|gadget|magisk|zygisk|riru|re\.frida)/i.test(nm)){ L('隐藏模块',nm); return 0; } }catch(e){}
      return realCb(info,size,d);
    },'int',['pointer','size_t','pointer']);
    return orig(ourCb,data);
  },'int',['pointer','pointer']));
  L('dl_iterate_phdr 已隐藏注入模块');
}

// ---------- 2) exit/_exit/abort 阻止自杀 ----------
function hookKill(){
  ['exit','_exit'].forEach(function(s){
    const p=sym(s); if(!p) return;
    Interceptor.replace(p, new NativeCallback(function(code){ L('拦截 '+s+'('+code+') -> 不退出'); /* 不调真 exit */ },'void',['int']));
    L('拦截',s);
  });
  const ab=sym('abort');
  if(ab){ Interceptor.replace(ab, new NativeCallback(function(){ L('拦截 abort -> 返回'); },'void',[])); L('拦截 abort'); }
}

// ---------- 3) 文件探针藏可疑路径 ----------
function hookFS(){
  const hide=[/\/su(\b|$)/i,/magisk/i,/frida/i,/xposed/i,/qemu/i,/goldfish/i,/\/proc\/self\/maps/i];
  ['access','stat','lstat','open','__open_2','fopen','__fopen_chk'].forEach(function(s){
    const p=sym(s); if(!p) return;
    Interceptor.attach(p,{ onEnter:function(a){
      try{ const path=a[0].readCString(); if(path && hide.some(r=>r.test(path))) this.blk=path; }catch(e){}
    }, onLeave:function(r){
      if(this.blk){ L('藏',this.blk); r.replace(ptr(s.startsWith('open')||s.startsWith('fopen')?0:-1)); }
    }});
  });
  L('文件探针就绪');
}

// ---------- 4) dlopen/dlsym 打点 + uncompress 抓 DEX 载荷 ----------
function hookDl2(){
  const o=sym('dlopen'); if(o) Interceptor.attach(o,{onEnter:function(a){ try{ L('dlopen',a[0].readCString()); }catch(e){} }});
  const d=sym('dlsym'); if(d) Interceptor.attach(d,{onEnter:function(a){ try{ L('dlsym',a[1].readCString()); }catch(e){} }});
  // uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen)
  const u=sym('uncompress');
  if(u){ Interceptor.attach(u, {
      onEnter:function(a){ this._dest=a[0]; this._destLenPtr=a[1]; this._src=a[2]; this._slen=a[3].toInt32(); },
      onLeave:function(ret){
        if(ret.toInt32()!==0) return;
        try{
          const n=this._destLenPtr.readU32();
          const bytes=this._dest.readByteArray(n);
          const h=new Uint8Array(bytes.slice(0,4));
          const isDex = h[0]===0x64&&h[1]===0x65&&h[2]===0x78; // 'dex'
          L('uncompress 输出 '+n+' 字节 DEX='+isDex);
          const f='/data/local/tmp/secsdk_payload'+(isDex?'.dex':'.bin');
          const F=new File(f,'wb'); F.write(bytes); F.flush(); F.close(); L('已落盘 '+f);
        }catch(e){ L('dump 失败',e); }
      }});
    L('uncompress 已挂钩 (DEX 载荷抓取)');
  }
}

// ---------- 6) RegisterNatives 枚举(看它注册了哪些 native) ----------
function hookRegNat(){
  try{
    const art=Process.findModuleByName('libart.so'); if(!art) return;
    let target=null;
    art.enumerateExports().forEach(function(e){
      if(!target && /RegisterNatives/.test(e.name)) target=e.address;
    });
    if(target){ Interceptor.attach(target,{ onEnter:function(a){ try{ L('RegisterNatives methods@'+a[2]+' count='+a[3].toInt32()); }catch(e){} }}); L('RegisterNatives 已挂钩'); }
    else L('未找到 RegisterNatives 导出');
  }catch(e){ L('RegNat err',e); }
}

// ---------- 5) Java loadLibrary 打点 ----------
Java.perform(function(){
  try{
    var SL=Java.use('java.lang.System');
    SL.loadLibrary.override ? null : null;
    SL.loadLibrary.implementation=function(n){ L('System.loadLibrary("'+n+'")'); return this.loadLibrary(n); };
    SL.loadLibrary0 && (SL.loadLibrary0.implementation=function(c,n){ L('System.loadLibrary0(...,"'+n+'")'); return this.loadLibrary0(c,n); });
    L('System.loadLibrary 打点就绪');
  }catch(e){ L('loadLibrary hook 失败',e); }
});

// ---------- 7) 网易易盾 VMP 桥: com.netease.nis.sdkwrapper.Utils.rL(Object[]) ----------
//    libsecsdk 的 VMP DEX 用这个唯一 native 桥回调 Java。钩它=看 VMP 在干啥。
function hookNisRl(){
  Java.perform(function(){
    try{
      var Utils=Java.use('com.netease.nis.sdkwrapper.Utils');
      Utils.rL.implementation=function(args){
        try{
          var arr=Java.cast(args, Java.use('[Ljava.lang.Object;'));
          var parts=[];
          for(var i=0;i<Math.min(arr.length,10);i++){
            parts.push(desc(arr[i]));
          }
          L('易盾 rL #'+arr.length+' [' + parts.join(', ') + ']');
        }catch(e){ L('rL 参数解析失败', e); }
        var r=this.rL(args);
        try{ L('   rL -> '+desc(r)); }catch(e){}
        return r;
      };
      L('网易易盾 Utils.rL 已挂钩 (VMP 桥)');
      Utils.showRiskMessage.implementation=function(ctx,msg){ L('*** 易盾风险提示: '+msg); return this.showRiskMessage(ctx,msg); };
      L('showRiskMessage 已挂钩');
    }catch(e){ L('Utils.rL hook 失败(类未加载?)', e); }
  });
}

setTimeout(function(){ hookDl(); hookKill(); hookFS(); hookDl2(); hookRegNat(); hookNisRl(); }, 0);
['libsecsdk.so'].forEach(function(m){
  var iv=setInterval(function(){ if(Process.findModuleByName(m)){ clearInterval(iv); L(m,'已加载'); } },200);
});
L('=== frida_secsdk.js 就绪 ===');
