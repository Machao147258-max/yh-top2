# 某环逆向 TOP2 · SO 分析包

> 内容 = **原生库(.so)** + **分析脚本(.py/.js)** + **unidbg 探针(.java)** + **依赖清单**。不含工具、不含资源、不含 IDA 数据库。
> 反作弊 / 反调试 **不在本包**（下一个章节）。

## 目录
```
某环逆向top2\
├─ 文章发布.md        ← 实战文章（IDA + Qiling + unidbg 全过程）
├─ README.md          ← 本文件
├─ requirements.txt   ← Python 依赖（实测 imports）
├─ so\                ← 13 个原生库（259 MB）
├─ scripts\           ← 313 个分析脚本（.py / .js）
└─ unidbg\            ← unidbg 探针（.java 源码 + run.cmd）
```

## 一、so/ — 原生库（13 个）
| SO | 大小 | 定性 |
| --- | --- | --- |
| libUnreal.so | 237 MB | UE 5.6.1 引擎主库 |
| libmxcore.so | 11.6 MB | 完美 IM 引擎（OpenSSL+curl）|
| libprimekit.so | 3.1 MB | 客户端网络 |
| libtprt.so | 1.7 MB | （另章）|
| libclient.so | 0.9 MB | Crashpad |
| libDfga_Catch.so | 0.9 MB | DFGA |
| libthemis.so (+nosvc+patched) | 0.8×3 | 加密/风控 |
| libmxcore_javasupport.so | 0.4 MB | IM JNI bridge（273 pwim_*）|
| libsecsdk.so | 0.3 MB | 安全 SDK |
| libturingmfa.so | 0.3 MB | 天御 MFA |
| libkycgm.so | 0.2 MB | 国密 SM2/SM4-CBC |

## 二、scripts/ — 脚本分类（313 个）
| 类 | 代表脚本 |
| --- | --- |
| 静态扫描/符号 | `scan_so*.py` `survey_so.py` `so_imports.py` `elf_sym.py` |
| 反汇编/反编译 | `disasm_func.py` `idat_analyze_so.py` `ida_decomp.py` |
| xref | `xref_any.py` `find_callers_of.py` `lookup_got.py` |
| IDA(idat/idalib) | `ida_*.py` `idat_*.py` |
| 加密/密钥 | `find_aes_key.py` `find_aes_sbox.py` `disasm_setkey.py` |
| Qiling 拟真 | `qiling_harness.py` `qiling_tprt_sim.py` `qiling_*.py` |
| Frida(.js) | `frida_stable.js` `frida_ssl_hook.js` `frida_dump.js` |
| SSL/证书 | `find_ssl_*.py` `find_realpins.py` |
| IoStore/Oodle | `find_oodle.py` `find_iostore.py` `utoc_*.py` `retoc_*.py` |

## 三、unidbg/ — 探针（.java 源码）
`Demo.java` / `MyJni.java`（修 4 处的 JNI 桥）/ `ProbeMxcoreJava.java` / `JavasupportProbe.java` / `TprtProbe.java` / `SecsdkProbe.java` / `KycgmDemo.java` / `MemDump.java` / `MemRawDump.java` / `SegDump.java` / `CombinedProbe.java` / `run.cmd`

## 四、requirements.txt
Python：`pyelftools capstone unicorn qiling androguard loguru pycryptodome lief numpy`
Qiling 额外：`python-registry gevent multiprocess questionary windows-curses`
非 pip：IDAPython（IDA 9.4）/ unidbg(JDK+Maven) / Frida(frida-tools+node) / Qiling rootfs(arm64_android)

## 五、核心命令
```bash
# IDA 反编译（脚本模式）
"D:\IDA Pro 9.4.260714\idat.exe" -A -S"scripts\ida_analyze_so.py" so\libUnreal.so
# Qiling 拟真（需源码版 qiling + rootfs，路径勿含中文）
python scripts\qiling_harness.py
# unidbg 探针（JDK+Maven）
cd unidbg && run.cmd
```
