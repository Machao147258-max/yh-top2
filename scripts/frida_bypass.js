/*
 * 异环 反检测绕过 —— 辅助 Frida 在【模拟器】上稳定运行
 * 目标: com.hottagames.yh.laohu (UE5.6.1 Android arm64)
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_bypass.js -l frida_dump.js
 * 依据: reports/41(反检测分析) + reports/43(检测/签名定位)
 *
 * 覆盖:
 *  1) 反调试   prctl(PR_SET_DUMPABLE/PTRACER) / ptrace(TRACEME) / TracerPid 抹除
 *  2) maps     /proc/self/maps 抹 frida/gum 行
 *  3) 属性     __system_property_get 返回干净值(去 root/magisk/emulator)
 *  4) 文件探针 access/stat/readlink/opendir/fopen 藏 su/magisk/frida/模拟器 路径
 *  5) 反注入   dl_iterate_phdr 过滤注入库
 *  6) 反作弊   libthemis(ThemisLite JNI) / libsecsdk(JNI_OnLoad) 打点
 *  7) 模拟器   /proc/cpuinfo、qemu 属性、goldfish/ranchu 文件 伪装
 */
'use strict';

const HIDE = ['frida','gum-js','gum-js-loop','gmain','gdbus','linjector','frida-agent',
              'frida-server','gadget','re.frida','/data/local/tmp/frida','/data/local/tmp/re.'];
const ROOT_PATHS = ['/su','/sbin/su','/system/bin/su','/system/xbin/su','/system/sbin/su',
                    'magisk','supersu','/data/adb','riru','zygisk','xposed','substrate',
                    'lsposed','edxposed','busybox','/system/lib/libmagisk'];
const EMU_PATHS = ['/dev/qemu_pipe','/dev/socket/qemud','/dev/goldfish','qemu','goldfish',
                   'ranchu','genymotion','bluestacks','libc_malloc_debug_qemu','/sys/qemu_trace',
                   'houdini','/dev/socket/genyd','/system/lib64/libhoudini','vbox','virtualbox'];
const EMU_SCRUB = ['goldfish','ranchu','qemu','genymotion','bluestacks','libhoudini','vbox','virtualbox'];
const PROP_FIX = {
  'ro.debuggable': '0', 'ro.secure': '1', 'ro.build.type': 'user',
  'ro.build.tags': 'release-keys', 'ro.build.selinux': '1',
  'service.adb.root': '0', 'ro.hardware.egl': 'adreno',
  'ro.kernel.qemu': '', 'ro.kernel.qemu.gles': '0', 'qemu.hw.mainkeys': '',
  'ro.boot.qemu': '', 'ro.boot.qemu.avd_name': '', 'ro.boot.qemu.gltransport': '',
  'ro.hardware': 'qcom', 'ro.board.platform': 'sm8550', 'ro.boot.hardware': 'qcom',
  'ro.product.model': 'SM-S9280', 'ro.product.manufacturer': 'samsung',
  'ro.product.brand': 'samsung', 'ro.product.device': 'e3q', 'ro.product.name': 'e3qxxx',
  'ro.build.product': 'e3q', 'ro.build.flavor': 'e3qxxx-user',
  'ro.build.fingerprint': 'samsung/e3qxxx/e3q:14/UP1A.231005.007/S9280ZCS3AXK1:user/release-keys',
  'ro.boot.verifiedbootstate': 'green', 'sys.boot_completed': '1',
};
const RET_MINUS1 = ['access','faccessat','stat','lstat','stat64','lstat64','__stat64','readlink'];
const RET_NULL   = ['opendir','fopen','__fopen_chk','open','__open_2'];

function L() { console.log.apply(console, ['[bypass]'].concat([].slice.call(arguments))); }
function hasHide(s){ return !!s && HIDE.some(k => s.toLowerCase().indexOf(k) !== -1); }
function isSuspicious(s){ return !!s && ROOT_PATHS.concat(EMU_PATHS).some(k => s.toLowerCase().indexOf(k) !== -1); }
function hasEmu(s){ return !!s && EMU_SCRUB.some(k => s.toLowerCase().indexOf(k) !== -1); }

function filterBuf(bufPtr, len) {
  try {
    const s = bufPtr.readUtf8String(len);
    if (!hasHide(s) && !/TracerPid:/.test(s) && !hasEmu(s)) return len;
    let lines = s.split('\n').filter(l => !hasHide(l) && !hasEmu(l));
    lines = lines.map(l => /TracerPid:/.test(l) ? 'TracerPid:\t0' : l);
    const kept = lines.join('\n');
    bufPtr.writeUtf8String(kept);
    return kept.length;
  } catch (e) { return len; }
}
function findSym(sym) {
  let p = null;
  try { p = Module.getExportByName(null, sym); } catch (e) {}
  if (!p) { try { p = Module.getExportByName('libc.so', sym); } catch (e) {} }
  return p;
}
function attach(sym, onEnter, onLeave) {
  const p = findSym(sym);
  if (!p) { L('未找到', sym); return; }
  Interceptor.attach(p, { onEnter: onEnter || function(){}, onLeave: onLeave || function(){} });
  L('hook', sym);
}
function replace(sym, sig, impl) {
  const p = findSym(sym);
  if (!p) { L('未找到', sym); return null; }
  const orig = new NativeFunction(p, sig.ret, sig.args);
  Interceptor.replace(p, new NativeCallback(impl(orig), sig.ret, sig.args));
  L('replace', sym);
  return orig;
}

function main() {
  L('arch =', Process.arch, Process.platform);

  // 1) 反调试
  replace('prctl', { ret:'int', args:['int','uint64','uint64','uint64','uint64'] }, function (orig) {
    return function (o,a,b,c,d) { if (o===21||o===39) { L('prctl 拦',o); return 0; } return orig(o,a,b,c,d); };
  });
  replace('ptrace', { ret:'long', args:['uint','uint','pointer','pointer'] }, function (orig) {
    return function (req,pid,addr,data) { if (req===0) { L('ptrace 拦 TRACEME'); return 0; } return orig(req,pid,addr,data); };
  });

  // 2) maps/status/cpuinfo 抹除
  const procFds = new Set();
  function trackOpen(sym) {
    attach(sym, function (args) { try { this.path = args[0].readCString(); } catch (e) { this.path = null; } },
      function (ret) {
        const fd = ret.toInt32();
        if (fd >= 0 && this.path && (/\/proc\/.*maps/.test(this.path) || /\/proc\/self\/status/.test(this.path) || /\/proc\/cpuinfo/.test(this.path))) {
          procFds.add(fd); L('标记 proc fd', fd, this.path);
        }
      });
  }
  trackOpen('open'); trackOpen('openat'); trackOpen('__open_2');
  ['read','pread','pread64'].forEach(function (sym) {
    attach(sym, function (a) { this.fd = a[0].toInt32(); this.buf = a[1]; },
      function (ret) { if (procFds.has(this.fd) && ret.toInt32() > 0) ret.replace(ptr('' + filterBuf(this.buf, ret.toInt32()))); });
  });
  attach('fgets', function (a) { this.buf = a[0]; }, function (ret) { if (!ret.isNull()) { try { filterBuf(this.buf, 512); } catch (e) {} } });
  L('proc 抹除就绪');

  // 3) __system_property_get 干净值
  replace('__system_property_get', { ret:'int', args:['pointer','pointer'] }, function (orig) {
    return function (nameP, valP) {
      let name = null; try { name = nameP.readCString(); } catch (e) {}
      if (name && PROP_FIX.hasOwnProperty(name)) { try { valP.writeUtf8String(PROP_FIX[name]); } catch (e) {} return PROP_FIX[name].length; }
      const r = orig(nameP, valP);
      if (name && (name.indexOf('ro.') === 0 || name.indexOf('init.svc') === 0 || name.indexOf('gsm.') === 0)) {
        try { const v = valP.readCString(); if (isSuspicious(v) || hasHide(v)) { valP.writeUtf8String(''); return 0; } } catch (e) {}
      }
      return r;
    };
  });

  // 4) 文件探针
  RET_MINUS1.forEach(function (s) {
    attach(s, function (args) { try { const p = args[0].readCString(); if (isSuspicious(p) || hasHide(p)) this.block = p; } catch (e) {} },
      function (ret) { if (this.block) { L('藏(-1)', this.block); ret.replace(ptr('-1')); } });
  });
  RET_NULL.forEach(function (s) {
    attach(s, function (args) { try { const p = args[0].readCString(); if (isSuspicious(p) || hasHide(p)) this.block = p; } catch (e) {} },
      function (ret) { if (this.block) { L('藏(NULL)', this.block); ret.replace(ptr(0)); } });
  });
  L('文件探针就绪');

  // 5) dl_iterate_phdr 过滤注入库
  try {
    const dp = Module.getExportByName(null, 'dl_iterate_phdr');
    const orig = new NativeFunction(dp, 'int', ['pointer','pointer']);
    Interceptor.replace(dp, new NativeCallback(function (cbPtr, data) {
      const realCb = new NativeFunction(cbPtr, 'int', ['pointer','size_t','pointer']);
      const ourCb = new NativeCallback(function (info, size, d) {
        try { const np = info.add(8).readPointer(); const name = np.isNull() ? null : np.readCString(); if (hasHide(name)) { L('dl_iterate 跳过', name); return 0; } } catch (e) {}
        return realCb(info, size, d);
      }, 'int', ['pointer','size_t','pointer']);
      return orig(ourCb, data);
    }, 'int', ['pointer','pointer']));
    L('dl_iterate_phdr 已挂');
  } catch (e) { L('dl_iterate err', e); }

  // 6) 反作弊: libthemis / libsecsdk
  const THEMIS = ['Java_com_taptap_sdk_themis_lite_ThemisLite_zXq3tVwP','Java_com_taptap_sdk_themis_lite_ThemisLite_vQe8bYsT',
                  'Java_com_taptap_sdk_themis_lite_ThemisLite_xJ3kLm9Q','Java_com_taptap_sdk_themis_lite_ThemisLite_Z8f7JxQk'];
  function hookThemis(){ const m = Process.findModuleByName('libthemis.so'); if (!m) return false;
    THEMIS.forEach(function (nm) { const a = m.findExportByName(nm); if (a) Interceptor.attach(a, { onEnter: function () { L('[反作弊] ThemisLite.' + nm.substr(nm.lastIndexOf('_')+1)); } }); });
    L('libthemis ThemisLite hooks 就绪'); return true; }
  function hookSecsdk(){ const m = Process.findModuleByName('libsecsdk.so'); if (!m) return false;
    const j = m.findExportByName('JNI_OnLoad'); if (j) Interceptor.attach(j, { onEnter: function () { L('[反作弊] libsecsdk JNI_OnLoad'); } });
    L('libsecsdk JNI_OnLoad 已挂'); return true; }
  if (!hookThemis()) { const iv = setInterval(function () { if (hookThemis()) clearInterval(iv); }, 200); }
  if (!hookSecsdk()) { const iv2 = setInterval(function () { if (hookSecsdk()) clearInterval(iv2); }, 200); }

  // 6c) strstr/memmem: needle 含检测词 → NULL
  function hookSearch(sym) {
    const p = findSym(sym); if (!p) { L('无', sym); return; }
    const isMem = (sym === 'memmem');
    const orig = new NativeFunction(p, 'pointer', isMem ? ['pointer','size_t','pointer','size_t'] : ['pointer','pointer']);
    Interceptor.replace(p, new NativeCallback(function (h, hn, n, nl) {
      try { const needle = isMem ? n.readUtf8String(nl.toInt32()) : hn.readCString(); if (needle && (hasHide(needle) || isSuspicious(needle) || hasEmu(needle))) return ptr(0); } catch (e) {}
      return isMem ? orig(h, hn, n, nl) : orig(h, hn);
    }, 'pointer', isMem ? ['pointer','size_t','pointer','size_t'] : ['pointer','pointer']));
    L('hook', sym);
  }
  hookSearch('strstr'); hookSearch('strcasestr'); hookSearch('memmem');

  L('* 模拟器: 已伪装 qemu 属性 + 抹 goldfish/ranchu 文件与 cpuinfo');
  L('* 仍需做: 1)Frida 改端口 27042/27043  2)frida-server/gadget 改名  3)magisk zygisk 隐藏');
  L('* 注意: DEX 签名校验(checkSignature/verifySignature)在 Java 层, 靠"内存 hook 不改盘"规避');
  L('=== bypass 完成 ===');
}

setTimeout(main, 0);
