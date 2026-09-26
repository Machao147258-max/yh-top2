/*
 * 针对【反作弊 / 反调试】的 Frida 脚本 (异环)
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_anticheat.js
 * 依据: reports/43,45 + GameActivity.java:4152
 *
 * 反作弊面:
 *  A. Java 反调试: android.os.Debug.isDebuggerConnected() -> GameActivity.nativeSetAndroidStartupState()
 *  B. native libsecsdk: 混淆VMP + 完整性 + dl_iterate_phdr(反注入) + exit/abort(自杀)
 *  C. SDK 签名自检: TapTap ThemisLite / 微信 / 支付宝 (SDK级, 非游戏自检)
 */
'use strict';
const TAG='[anticheat]';
function L(){ console.log.apply(console, [TAG].concat([].slice.call(arguments))); }

// ---------- A. Java 反调试 ----------
Java.perform(function () {
  // 1) Debug.isDebuggerConnected -> false
  try {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () { L('Debug.isDebuggerConnected -> false'); return false; };
    Debug.waitingForDebugger.implementation = function () { L('Debug.waitingForDebugger -> false'); return false; };
    L('Debug 已挂钩');
  } catch (e) { L('Debug hook 失败', e); }

  // 2) GameActivity.nativeSetAndroidStartupState(bool) -> 传 false
  try {
    var GA = Java.use('com.epicgames.unreal.GameActivity');
    GA.nativeSetAndroidStartupState.implementation = function (b) { L('nativeSetAndroidStartupState('+b+') -> 强制 false'); return this.nativeSetAndroidStartupState(false); };
    L('GameActivity.nativeSetAndroidStartupState 已挂钩');
  } catch (e) { L('GameActivity hook 失败(可忽略)', e); }

  // 3) 顺带堵 SDK 签名自检里的 getPackageInfo(GET_SIGNATURES) 不需要; 保留真实签名即可
});

// ---------- B. native libsecsdk ----------
function hookLib(){
  // dl_iterate_phdr 过滤注入库 (libsecsdk/libthemis 都用来反注入)
  try {
    var dp = Module.getExportByName(null, 'dl_iterate_phdr');
    var orig = new NativeFunction(dp, 'int', ['pointer','pointer']);
    Interceptor.replace(dp, new NativeCallback(function (cbPtr, data) {
      var realCb = new NativeFunction(cbPtr, 'int', ['pointer','size_t','pointer']);
      var ourCb = new NativeCallback(function (info, size, d) {
        try { var np = info.add(8).readPointer(); var name = np.isNull()?null:np.readCString();
          if (name && /(frida|gum|linjector|gadget|magisk|zygisk|riru)/i.test(name)) { L('dl_iterate 跳过', name); return 0; } } catch(e){}
        return realCb(info, size, d);
      }, 'int', ['pointer','size_t','pointer']);
      return orig(ourCb, data);
    }, 'int', ['pointer','pointer']));
    L('dl_iterate_phdr 已过滤注入库');
  } catch (e) { L('dl_iterate err', e); }

  // exit/abort: 打点(看完整性校验是否触发自杀), 不阻断(避免副作用)
  ['exit','_exit','abort'].forEach(function(s){
    var p=null; try{p=Module.getExportByName(null,s);}catch(e){}
    if(!p) return;
    Interceptor.attach(p, { onEnter: function(a){
      var st = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0,4).map(DebugSymbol.fromAddress).join(' <- ');
      L('!!! '+s+' 被调用, 栈: '+st);
    }});
    L('监控', s);
  });
}
setTimeout(hookLib, 0);

// 模块加载后重挂(应对 libsecsdk 晚加载)
['libsecsdk.so','libthemis.so'].forEach(function(m){
  var iv=setInterval(function(){ if(Process.findModuleByName(m)){ clearInterval(iv); L(m,'已加载'); } },200);
});

L('=== frida_anticheat.js 就绪 ===');
