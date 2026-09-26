/*
 * 针对 libthemis.so 的 Frida 脚本 (异环 / TapTap ThemisLite)
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_themis.js
 * 依据: reports/43 (唯一真反调试 = libthemis prctl @0x71f0c; 触发链 JNI→0x7c144→0x71e8c)
 *
 * 覆盖:
 *  1) prctl 反调试(21 PR_SET_DUMPABLE / 39 PR_SET_PTRACER) -> 0
 *  2) 反调试函数 libthemis+0x71e8c -> 直接返回 (可选, 激进)
 *  3) ThemisLite 4 个 JNI 入口 打点 + 可选中和
 *  4) 环境检测原语 (__system_property_get / memmem / access / readlink)
 *
 * 注意: libthemis 部分检测用【直接 syscall(SVC)】绕过 libc hook,
 *       那些只能在 JNI 边界(2/3)或内核层处理。
 */
'use strict';
const M = 'libthemis.so';
const OFF_ANTIDEBUG = 0x71E8C;   // 含 prctl(21/39) 的函数
const THEMIS = {
  'Java_com_taptap_sdk_themis_lite_ThemisLite_zXq3tVwP': 0x33440,
  'Java_com_taptap_sdk_themis_lite_ThemisLite_vQe8bYsT': 0x334a0,
  'Java_com_taptap_sdk_themis_lite_ThemisLite_xJ3kLm9Q': 0x33600,
  'Java_com_taptap_sdk_themis_lite_ThemisLite_Z8f7JxQk': 0x33670,
};
const NEUTRALIZE_JNI = false;  // 设 true 则 JNI 直接返回 0 (可能影响反作弊上报)
const KILL_ANTIDEBUG_FN = true; // 直接把 0x71e8c 变 no-op

function L(){ console.log.apply(console, ['[themis]'].concat([].slice.call(arguments))); }
function findSym(sym){ let p=null; try{p=Module.getExportByName(null,sym);}catch(e){} if(!p){try{p=Module.getExportByName('libc.so',sym);}catch(e){}} return p; }

function main(){
  const m = Process.findModuleByName(M);
  if (!m) { L('等待', M, '...'); const iv=setInterval(()=>{ if(Process.findModuleByName(M)){clearInterval(iv); main();} },200); return; }
  L('base =', m.base, 'size =', m.size);

  // 1) prctl 反调试 -> 0
  const pp = findSym('prctl');
  if (pp) {
    const orig = new NativeFunction(pp, 'int', ['int','uint64','uint64','uint64','uint64']);
    Interceptor.replace(pp, new NativeCallback(function(o,a,b,c,d){
      if (o===21 || o===39) { L('prctl('+o+') 拦截 ->0'); return 0; }
      return orig(o,a,b,c,d);
    }, 'int', ['int','uint64','uint64','uint64','uint64']));
    L('prctl hook 就绪 (21/39 -> 0)');
  } else L('找不到 prctl');

  // 2) 反调试函数 -> no-op (可选)
  if (KILL_ANTIDEBUG_FN) {
    const fn = m.base.add(OFF_ANTIDEBUG);
    Interceptor.replace(fn, new NativeCallback(function(){ L('[反调试函数 0x71e8c] 拦 -> 立即返回'); return 0; }, 'int', []));
    L('反调试函数 0x71e8c 已 no-op');
  }

  // 3) ThemisLite JNI
  Object.keys(THEMIS).forEach(function(nm){
    let a = null;
    try { a = m.findExportByName(nm); } catch(e){}
    if (!a) { a = m.base.add(THEMIS[nm]); }
    if (!a) return;
    if (NEUTRALIZE_JNI) {
      Interceptor.replace(a, new NativeCallback(function(){ L('[JNI中和]', nm.split('_').pop()); return 0; }, 'pointer', ['pointer','pointer']));
    } else {
      Interceptor.attach(a, { onEnter: function(args){ L('[JNI]', nm.split('_').pop(), 'env='+args[0], 'obj='+args[1]); } });
    }
    L('hook', nm.split('_').pop(), a);
  });

  // 4) 环境检测原语
  try {
    const sp = findSym('__system_property_get');
    if (sp) {
      const orig = new NativeFunction(sp, 'int', ['pointer','pointer']);
      Interceptor.replace(sp, new NativeCallback(function(n,v){
        let name=null; try{name=n.readCString();}catch(e){}
        if (name && /^(ro\.(product|build|boot|hardware|kernel)|gsm\.)/.test(name)) { return orig(n,v); } // 交给 frida_bypass 的通用伪造
        return orig(n,v);
      }, 'int', ['pointer','pointer']));
      L('__system_property_get 已挂(配合 frida_bypass 的 PROP_FIX)');
    }
  } catch(e){}
  function nul(sym){
    const p=findSym(sym); if(!p) return;
    Interceptor.attach(p, { onEnter:function(a){ try{ const s=a[0].readCString(); if(s && /(frida|gum|magisk|su|qemu|goldfish|xposed)/i.test(s)){ this.blk=s; } }catch(e){} },
      onLeave:function(r){ if(this.blk){ L('藏',sym,this.blk); } } });
  }
  ['access','readlink','opendir','fopen'].forEach(nul);

  L('=== frida_themis.js 就绪 (配合 frida_bypass.js 使用更佳) ===');
}
setTimeout(main, 0);
