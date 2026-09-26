/*
 * frida_themis_svc.js —— 处理 libthemis 的【内联 svc】(libc 钩不到)
 * 实测(libthemis .text 8 条 svc#0):
 *   0x3345c/0x334f4/0x3361c/0x336c0 : x8=0xae=174 = getuid()  (无害, 不动)
 *   0x33d38 / 0x356a8               : x8=0x38 = 56 = openat()  <-- 绕 libc, 需处理
 *   0x34d28 / 0x3585c               : x8=0x39 = 57 = close()   (无害)
 * 原理: 把内联 openat 的 `svc #0`(01 00 00 d4) 原地 patch 成 `movn x0,#0`(x0=-1) => 打开失败(等价"读不到/不存在")
 *       —— 与 libc 层把 /proc/self/* 洗白/返回不存在同效。
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_themis_svc.js
 */
'use strict';
const T='[themis-svc]';
function L(){ console.log.apply(console,[T].concat([].slice.call(arguments))); }
function patch4(mod, off, kind){
  try{
    const a = mod.base.add(off);
    // 校验当前确实是 svc#0 (01 00 00 d4)
    const cur = a.readByteArray(4);
    const b = new Uint8Array(cur);
    const isSvc = (b[0]===0x01 && b[1]===0x00 && b[2]===0x00 && b[3]===0xd4);
    const bytes = (kind==='fail') ? [0x00,0x00,0x80,0x92]   // movn x0,#0 -> x0 = -1
                                   : [0xe0,0x03,0x1f,0xaa]; // mov x0, xzr -> 0
    Memory.patchCode(a, 4, function(code){ code.writeByteArray(bytes); });
    L('patched '+mod.name+' +0x'+off.toString(16)+' ('+kind+') svc?='+isSvc);
  }catch(e){ L('patch fail +0x'+off.toString(16)+' '+e); }
}
const th = Process.findModuleByName('libthemis.so');
if(th){
  patch4(th, 0x33d38, 'fail');   // 内联 openat -> -1
  patch4(th, 0x356a8, 'fail');   // 内联 openat -> -1
  L('libthemis 内联 openat 已 patch (base='+th.base+')');
} else { L('libthemis.so 未加载'); }

// 备选(更彻底, 但重): 用 Stalker 在指令级拦所有 svc
// Stalker.follow(Process.getCurrentThreadId(), {
//   transform: function(iterator){
//     var ins = iterator.next();
//     while(ins !== null){
//       if(ins.mnemonic === 'svc'){ iterator.putCallout(function(ctx){
//           var nr = ctx.x8.toInt32();
//           if(nr===56){ ctx.x0 = ptr(-1); ctx.pc = ctx.pc.add(4); }  // openat -> 跳过 svc
//           if(nr===57){ ctx.x0 = ptr(0);  ctx.pc = ctx.pc.add(4); }  // close
//       }); }
//       iterator.keep(); ins = iterator.next();
//     }
//   }
// });
