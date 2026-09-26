/*
 * 异环(yh) 反检测 Frida 脚本骨架  —  据报告66 定位
 * 用法(推荐): frida -U -f com.hottagames.yh.laohu -l yh_frida_hooks.js --no-pause
 * 说明: 目标是"过检测", 请用改名/无 "frida" 字样的 server 或 gadget, 否则 /proc/self/maps 里出现 frida 字样会被图灵盾(Turingface)抓到。
 */

/* ============ Layer 1: Java 层 —— 把检测方法改成安全值 ============ */
function U(n){ try { return Java.use(n); } catch(e){ return null; } }

Java.perform(function(){
  // ---- 腾讯图灵盾 Turingcam (反调试: TracerPid、/proc/self/status) ----
  var tc = U("com.tencent.turingcam.oqKCa");
  if (tc) {
    try { tc.b.overload('android.content.Context').implementation = function(c){ return 0; };      } catch(e){}
    try { tc.a.overload('android.content.Context').implementation = function(c){ return 0; };      } catch(e){}
    try { tc.f.overload().implementation = function(){ return false; };                            } catch(e){}
    ['i','j','l','m'].forEach(function(mn){
      try { tc[mn].overload('android.content.Context').implementation = function(c){ return false; }; } catch(e){}
    });
    console.log("[hook] turingcam.oqKCa");
  }
  // ---- 腾讯图灵盾 Turingface (反注入: /proc/self/maps、mountinfo) ----
  var l32 = U("com.tencent.turingface.sdk.mfa.L32b7");
  if (l32) {
    try { l32.a.overload('android.content.Context').implementation = function(c){ return ""; };       } catch(e){}
    try { l32.a.overload('android.content.Context','java.lang.String').implementation = function(c,s){ return ""; }; } catch(e){}
    try { l32.a.overload().implementation = function(){ return false; };                              } catch(e){}
    console.log("[hook] turingface.L32b7");
  }
  var rbd = U("com.tencent.turingface.sdk.mfa.rBDKv");
  if (rbd) { try { rbd.a.overload('android.content.Context').implementation = function(c){ return null; }; } catch(e){} }

  // ---- com.wpsdk.dfga (反 Xposed: de.robv.android.xposed.XposedBridge) ----
  var dfga = U("com.wpsdk.dfga.sdk.utils.a.e");
  if (dfga) { try { dfga.b.overload().implementation = function(){ return false; }; } catch(e){} console.log("[hook] dfga...a.e.b"); }

  // ---- Alipay (qemu/root) ----
  var a0b = U("com.alipay.sdk.m.a0.b");
  if (a0b) { ['s','o','g','u','v'].forEach(function(mn){ try{ a0b[mn].overload().implementation=function(){return "";}; }catch(e){} }); }
  var a0e = U("com.alipay.sdk.m.a0.e");
  if (a0e) { try{ a0e.c.overload().implementation=function(){return false;}; }catch(e){} try{ a0e.d.overload().implementation=function(){return false;}; }catch(e){} }
  var msb = U("com.alipay.sdk.m.s.b");
  if (msb) { try{ msb.e.overload().implementation=function(){return false;}; }catch(e){} }

  // ---- 异环自研 (/proc/self/maps) ----
  var yhw = U("com.hottagames.yhwrapper.a");
  if (yhw) { try{ yhw.b.overload('java.lang.String','java.lang.String').implementation=function(a,b){return false;}; }catch(e){} }

  // ---- Bugly (root/debugger) ----
  var ab = U("com.tencent.bugly.idasc.proguard.ab");
  if (ab) { ['o','p','q','r','s'].forEach(function(mn){ try{ ab[mn].overload().implementation=function(){return false;}; }catch(e){} }); }

  console.log("[java] 反检测 hooks 已装 (可视需要开启更多)");
});

/* ============ Layer 2: libc 层 —— 过滤敏感文件/路径 (最强兜底) ============ */
var SENS = [
  "/proc/self/maps", "/proc/self/status", "/proc/self/mountinfo", "/proc/self/task",
  "/proc/self/cmdline", "/proc/self/net/tcp", "/proc/self/net/tcp6", "/proc/self/smaps",
  "/sbin/su", "/system/xbin/su", "/system/bin/su", "/su/bin/su",
  "/dev/qemu_pipe", "/dev/socket/qemud", "/sys/qemu_trace", "/system/bin/qemu-props",
  "magisk", "frida", "gadget", "gum-js", "linjector"
];
function isSens(p){ if(!p) return false; var s=p.toLowerCase(); for(var i=0;i<SENS.length;i++){ if(s.indexOf(SENS[i])>=0) return true; } return false; }
function cstr(p){ try { return p.readCString(); } catch(e){ return null; } }

var libc = Process.getModuleByName("libc.so");
// 打开类: 命中敏感路径 -> 失败(骗过"是否存在/能否读")
["fopen","fopen64","__open_2","open","openat"].forEach(function(fn){
  try {
    var f = Module.findExportByName("libc.so", fn);
    if (!f) return;
    Interceptor.attach(f, {
      onEnter: function(a){
        // fopen(path,mode) / open(path,flags) ; openat(dirfd,path,flags)
        var path = (fn==="openat") ? cstr(a[1]) : cstr(a[0]);
        this.sens = isSens(path);
        if (this.sens) console.log("[libc] "+fn+"('"+path+"') -> ENOENT");
      },
      onLeave: function(r){
        if (this.sens) r.replace(ptr(-2)); // NULL (fopen) 或 -1 (open)
      }
    });
  } catch(e){}
});
// 属性读取: 假造 ro.kernel.qemu / ro.debuggable / ro.secure
try {
  var sp = Module.findExportByName("libc.so", "__system_property_get");
  if (sp) Interceptor.attach(sp, {
    onEnter: function(a){ this.k = cstr(a[0]); this.out = a[1]; },
    onLeave: function(r){
      if (this.k === "ro.kernel.qemu") { this.out.writeUtf8String("0"); r.replace(1); }
      else if (this.k === "ro.debuggable") { this.out.writeUtf8String("0"); r.replace(1); }
      else if (this.k === "ro.secure")     { this.out.writeUtf8String("1"); r.replace(1); }
    }
  });
} catch(e){}
// ptrace 自附加反调试
try {
  var pt = Module.findExportByName("libc.so", "ptrace");
  if (pt) Interceptor.attach(pt, { onLeave: function(r){ r.replace(ptr(0)); } });
} catch(e){}

/* ====== 说明 ======
 * 1) /proc/self/maps 更稳的做法: 不返回 NULL, 而是用 memfd 返回"洗掉 frida/gum/linjector 行"的副本。
 *    很多检测是 fopen(maps)+逐行 strstr("frida"); 返回 NULL 多数也能过。
 * 2) 图灵盾/dfga 的原生部分(libDfga_Catch.so、libmxcore.so) 若绕过 libc 直接 syscall,
 *    需按 base+offset 单独 Interceptor.attach (报告66; 待逆)。
 * 3) 启动用 -f(spawn) 且尽早装载, 因为这些检测在冷启动就执行。
 * 4) libsecsdk(VMP) 的插桩另行处理: rL native = libsecsdk.base + 0xaddc; 解释器主循环 = base + 0x307b8。
 */
