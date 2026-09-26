/*
 * 针对 libthemis 的【Java 层】Frida 脚本 —— 最干净(绕开 native 全部混淆/反调试/syscall)
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_themis_java.js
 * 依据: com.taptap.sdk.themis.lite.{ThemisLite,ThemisLiteManager}
 *
 * 原理: ThemisLite 的 4 个方法都是 private static native。
 *       在 Java 边界替换 -> libthemis.so 的 native 逻辑永不执行
 *       -> prctl 反调试 / maps 扫描 / 设备检测 / 上报 全部失效。
 */
'use strict';
const TAG = '[themis-java]';
function L(){ console.log.apply(console, [TAG].concat([].slice.call(arguments))); }

// 模式: 'skip'   = 整个 native 初始化不跑 (推荐, 最彻底)
//       'fakeid' = 让 native 跑, 但把取回的 tdid/oneid 换成假值
const MODE = 'skip';
const FAKE_TDID = '0000000000000000';
const FAKE_ONEID = '{}';

Java.perform(function () {
  try {
    var ThemisLite = Java.use('com.taptap.sdk.themis.lite.ThemisLite');

    if (MODE === 'skip') {
      // InitThemis_v2(String appID, ThemisLiteCallback cb, long timeout, String preOneID, boolean a, boolean b)
      ThemisLite.InitThemis_v2.implementation = function (appID, cb, timeout, preOneID, a, b) {
        L('InitThemis_v2 拦截 -> 跳过 native 初始化');
        // 主动回调假值, 避免上层一直等 tdid
        try {
          if (cb !== null) {
            cb.getThemisTapaid(FAKE_TDID);
            cb.getThemisOneIDData(FAKE_ONEID);
          }
        } catch (e) { L('回调假值失败', e); }
        return;
      };
      L('InitThemis_v2 -> no-op');
    }

    // 无论如何都替换两个 ID provider (native 若跑了也返回假值)
    ThemisLite.xJ3kLm9Q.implementation = function () { L('xJ3kLm9Q -> 假 tdid'); return FAKE_TDID; };
    ThemisLite.zXq3tVwP.implementation = function () { L('zXq3tVwP -> 假 oneid'); return FAKE_ONEID; };
    L('xJ3kLm9Q / zXq3tVwP -> 假值');

    // InitThemis_v2 里 vQe8bYsT(preOneID) 也堵掉
    ThemisLite.vQe8bYsT.implementation = function (s) { L('vQe8bYsT 拦截'); return; };
    ThemisLite.Z8f7JxQk.implementation = function (s, z, z2, j) { L('Z8f7JxQk 拦截'); return; };
    L('Z8f7JxQk / vQe8bYsT -> no-op');

  } catch (e) { L('ThemisLite hook 失败(可能类未加载)', e); }

  // Manager: 顺带看谁在调用 initialize (定位业务调用点)
  try {
    var Mgr = Java.use('com.taptap.sdk.themis.lite.ThemisLiteManager');
    Mgr.initialize.implementation = function (preOneID) {
      var st = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new());
      L('ThemisLiteManager.initialize 调用点:\n' + st);
      return this.initialize(preOneID);   // 仍执行(配合上面 InitThemis_v2 的拦截)
    };
    L('ThemisLiteManager.initialize 已打点');
  } catch (e) { L('Manager 未就绪(可忽略)', e); }

  L('=== 就绪: libthemis native 逻辑已被 Java 层短路 ===');
});
