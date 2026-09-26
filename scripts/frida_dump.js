/*
 * 异环 (NTE) — libUnreal.so Pak 解密 动态 dump 脚本
 * 用法: frida -U -f <pkg> -l frida_dump.js   (或 -n <进程名> -l)
 * 目标: hook 索引解密包装 + AES.SetKey + Oodle, dump 明文索引 / key
 * 地址为 libUnreal.so 内偏移(基址 0), 脚本自动加 module base。
 */
'use strict';

var MOD = 'libUnreal.so';
var OFF_DECRYPT = 0x3AC7CA8;   // 索引解密包装 sub_3AC7CA8
var OFF_SETKEY  = 0xABFA760;   // AES 类 SetKey
var OFF_ENC     = 0xABFA9A8;   // AES 类 Encrypt
var OFF_DEC     = 0xABFA8E0;   // AES 类 Decrypt
var OFF_OODLE   = 0xB587284;   // OodleLZ_Decompress 外壳
var OFF_IDXLOAD = 0x3ADA03C;   // 索引加载器

function hexdump(p, n) {
  try { return hexdumpRaw(p, n); } catch (e) { return '<' + e + '>'; }
}
function hexdumpRaw(p, n) {
  var out = '', b = [];
  for (var i = 0; i < n; i++) {
    var v = p.add(i).readU8().toString(16); if (v.length < 2) v = '0' + v; b.push(v);
    if ((i & 15) === 15 || i === n - 1) { out += b.join(' ') + '\n'; b = []; }
  }
  return out;
}

function hookBase(off, onEnter, onLeave) {
  var m = Process.findModuleByName(MOD);
  if (!m) { console.log('[!] 未找到 ' + MOD); return; }
  var addr = m.base.add(off);
  Interceptor.attach(addr, {
    onEnter: onEnter || function () {},
    onLeave: onLeave || function () {}
  });
  console.log('[+] hook ' + MOD + '+0x' + off.toString(16) + ' @ ' + addr);
}

function main() {
  var m = Process.findModuleByName(MOD);
  console.log('[*] ' + MOD + ' base = ' + (m ? m.base : '??'));
  if (Process.arch === 'arm64') { console.log('[*] arch=arm64'); }

  // 1) 索引解密包装: 记录入参 + 返回后 dump 解密结果
  hookBase(OFF_DECRYPT,
    function (args) {
      this.buf = args[0]; this.size = args[1].toInt32();
      console.log('\n[DECRYPT] buf=' + args[0] + ' size=0x' + this.size.toString(16) +
                  ' a3=0x' + args[2].toString(16) + ' a4=0x' + args[3].toString(16));
      try { console.log('  密文前32B:\n' + hexdump(this.buf, 32)); } catch (e) {}
    },
    function (retval) {
      console.log('[DECRYPT] 返回 0x' + retval.toString(16) + ' 解密后前64B:');
      try { console.log(hexdump(this.buf, Math.min(64, this.size))); } catch (e) {}
      try { send({ tag: 'index_decrypted', size: this.size,
                   data: this.buf.readByteArray(Math.min(this.size, 0x11320)) }); } catch (e) {}
    });

  // 2) AES SetKey: dump key
  hookBase(OFF_SETKEY,
    function (args) {
      // SetKey(this, TArray{data@0,num@8,max@12}, unused)
      var t = args[1];
      try {
        var p = t.readPointer(), n = t.add(8).readU32();
        console.log('\n[SetKey] key len=' + n + ' key=' + hexdumpRaw(p, Math.min(n, 64)).replace(/\n/g, ''));
        send({ tag: 'aes_key', len: n, key: p.readByteArray(Math.min(n, 64)) });
      } catch (e) { console.log('[SetKey] 读参失败 ' + e); }
    });

  // 3) AES Enc/Dec 调用计数(前几次)
  var cntE = 0, cntD = 0;
  hookBase(OFF_ENC, function (a) { if (cntE++ < 8) console.log('[Enc] this=' + a[0] + ' in=' + a[2] + ' len=' + a[3]); });
  hookBase(OFF_DEC, function (a) { if (cntD++ < 8) console.log('[Dec] this=' + a[0] + ' in=' + a[2] + ' len=' + a[3]); });

  // 4) Oodle 解压: 记录压缩大小
  hookBase(OFF_OODLE, function (a) {
    console.log('[Oodle] comp=' + a[0] + ' compLen=' + a[1] + ' raw=' + a[2] + ' rawLen=' + a[3]);
  });

  // 5) 索引加载器入口
  hookBase(OFF_IDXLOAD, function (a) {
    console.log('\n[LoadIndex] a1=' + a[0] + ' (a1+128=IndexOffset, +136=IndexSize, +144=IndexHash, +164=GUID)');
    try {
      console.log('   IndexOffset=0x' + a[0].add(128).readU64().toString(16) +
                  ' IndexSize=0x' + a[0].add(136).readU64().toString(16) +
                  ' GUID=' + hexdumpRaw(a[0].add(164), 16).replace(/\n/g, ''));
    } catch (e) {}
  });

  console.log('[*] hook 完成。让游戏加载 pak (进入游戏/登录) 即可看到输出。');
}

setTimeout(main, 0);
