/* ============================================================
 * libmxcore.so SSL 层 Frida hook 脚本 (异环 / wanmei-im)
 * 用法: frida -U -f <包名> -l frida_ssl_hook.js
 *       或 frida -U -n <进程名> -l frida_ssl_hook.js
 *
 * 偏移来自静态分析 (vaddr==file offset):
 *   reports/19_SSL层全景.md, reports/20_Qiling补环境.md
 * ============================================================ */

const MODULE = 'libmxcore.so';

// 关键函数偏移
const OFF = {
  InitSSL:      0x2BB570,  // CT::SSLContext::_InitSSL(this)
  VerifyCB:     0x2BBA70,  // SSL_CTX_set_verify 回调 (int cb(int ok, X509_STORE_CTX*))
  Handshake:    0x2BB7DC,  // 握手/I-O 驱动
  SSLWrite:     0x46AA74,  // SSL_write 包装(ctx, idx, buf, len, out)
  WritePrim:    0x489DBC,  // 真实写(ssl, buf, len)
  Connect:      0x1ECEA0,  // 连接层(host, port...)
  LogFn:        0x0AFA68,  // 内部日志(可屏蔽)
};

let BASE = null;

function base() {
  if (!BASE) BASE = Module.findBaseAddress(MODULE);
  if (!BASE) { console.log('[!] ' + MODULE + ' 未加载'); }
  return BASE;
}

// 读 C 字符串
function cstr(p) {
  if (!p || p.isNull()) return null;
  try { return p.readCString(); } catch (e) { return null; }
}

// 读 buffer 为 hex/ascii 预览
function dumpBuf(p, len, max) {
  max = max || 64;
  if (!p || p.isNull() || len <= 0) return '';
  const n = Math.min(len, max);
  try {
    const bytes = new Uint8Array(p.readByteArray(n));
    let hex = '', asc = '';
    for (const b of bytes) {
      hex += b.toString(16).padStart(2, '0') + ' ';
      asc += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
    }
    return `len=${len}\n        HEX: ${hex}\n        ASC: ${asc}`;
  } catch (e) { return `<dump err ${e}>`; }
}

function attach(offset, name, opts) {
  opts = opts || {};
  const b = base(); if (!b) return;
  Interceptor.attach(b.add(offset), {
    onEnter(args) { if (opts.onEnter) opts.onEnter(args, this); },
    onLeave(ret) { if (opts.onLeave) opts.onLeave(ret, this); }
  });
  console.log('[+] hook ' + name + ' @ ' + b.add(offset));
}

function main() {
  console.log('[*] libmxcore.so base = ' + base());

  // ---- CT::SSLContext::_InitSSL(this) ----
  attach(OFF.InitSSL, '_InitSSL', {
    onEnter(args) {
      this.thisPtr = args[0];
      console.log(`\n[_InitSSL] this=${args[0]}`);
    },
    onLeave(ret, ctx) {
      try {
        const t = ctx.thisPtr;
        console.log(`[_InitSSL] 完成: SSL_CTX=${t.add(8).readPointer()}` +
                    ` SSL=${t.add(0x10).readPointer()}` +
                    ` BIO_r=${t.add(0x18).readPointer()}` +
                    ` BIO_w=${t.add(0x20).readPointer()}`);
      } catch (e) {}
    }
  });

  // ---- verify 回调 cb(int ok, X509_STORE_CTX*) ----
  attach(OFF.VerifyCB, 'verifyCB', {
    onEnter(args) {
      console.log(`[verifyCB] preverify_ok=${args[0].toInt32()}`);
    }
  });

  // ---- SSL_write 包装 (ctx, idx, buf, len, out) ----
  attach(OFF.SSLWrite, 'SSL_write', {
    onEnter(args) {
      const len = args[3].toInt32();
      console.log(`\n[SSL_write] ctx=${args[0]} idx=${args[1].toInt32()} len=${len}`);
      console.log(`  明文: ${dumpBuf(args[2], len, 256)}`);
    },
    onLeave(ret) {
      console.log(`[SSL_write] ret=${ret.toInt32()}`);
    }
  });

  // ---- 真实写原语 (ssl, buf, len) ----
  attach(OFF.WritePrim, 'write_prim', {
    onEnter(args) {
      console.log(`[write_prim] ssl=${args[0]} buf=${args[1]} len=${args[2].toInt32()}`);
    }
  });

  // ---- 握手驱动 ----
  attach(OFF.Handshake, 'handshake', {
    onEnter(args) { console.log(`[handshake] this=${args[0]}`); }
  });

  // ---- 连接层 ----
  attach(OFF.Connect, 'Connect', {
    onEnter(args) { console.log(`\n[Connect] args: ${args[0]} ${args[1]} ${args[2]}`); }
  });

  console.log('[*] SSL hooks 就绪');
}

// 等待模块加载
(function () {
  if (Module.findBaseAddress(MODULE)) main();
  else {
    console.log('[*] 等待 ' + MODULE + ' ...');
    const iv = setInterval(() => {
      if (Module.findBaseAddress(MODULE)) { clearInterval(iv); main(); }
    }, 200);
  }
})();
