/*
 * frida_svc_patch.js —— 统一处理各库的【内联 svc】(libc 钩不到的)
 * 实测(仅 8+6+1 条):
 *   libthemis.so: 0x33d38/0x356a8 = openat(56)  -> patch 成 movn x0,#0 (打开失败)
 *                 (0x3345c..getuid, 0x34d28..close = 无害)
 *   libtprt.so  : 6× svc(x8=94=exit_group) -> patch 成 mov x0,xzr (去掉"检测即自杀/闪退")
 *                 sites: 0x2603c 0x3a614 0x3a640 0x3b6b8 0x3b8dc 0x3ba3c
 *   libturingmfa.so: 1× 未知 svc(0x36edc, x8 计算得出) -> 不处理(可选 Stalker 兜)
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_stable.js -l frida_svc_patch.js --no-pause
 */
'use strict';
const T='[svc-patch]';
function L(){ console.log.apply(console,[T].concat([].slice.call(arguments))); }
const SVC = [0x01,0x00,0x00,0xd4];           // svc #0
const MOVN_X0_0 = [0x00,0x00,0x80,0x92];     // movn x0, #0  -> x0 = -1
const MOV_X0_ZR = [0xe0,0x03,0x1f,0xaa];     // mov x0, xzr  -> x0 = 0
function patch(mod, off, bytes){
  try{
    const a=mod.base.add(off);
    const cur=!!(a.readByteArray(4) && new Uint8Array(a.readByteArray(4)).every((v,i)=>v===SVC[i]));
    Memory.patchCode(a, 4, c=>c.writeByteArray(bytes));
    L(mod.name+' +0x'+off.toString(16)+' patched (was svc='+cur+')');
  }catch(e){ L('patch fail +0x'+off.toString(16)+' '+e); }
}
function onModule(name, cb){ var m=Process.findModuleByName(name); if(m){ try{cb(m);}catch(e){} return; }
  var n=0,iv=setInterval(function(){ var x=Process.findModuleByName(name); if(x||++n>1200){ clearInterval(iv); if(x){try{cb(x);}catch(e){}} } },100); }
onModule('libthemis.so', function(th){ patch(th,0x33d38,MOVN_X0_0); patch(th,0x356a8,MOVN_X0_0); });
onModule('libtprt.so',   function(tp){ [0x2603c,0x3a614,0x3a640,0x3b6b8,0x3b8dc,0x3ba3c].forEach(o=>patch(tp,o,MOV_X0_ZR)); });
L('done.');
