"""
通用 Qiling harness: 加载 SO + 打桩所有导入 + 调用任意函数
- 解析 .rela.plt，为每个导入分配桩地址、回填 GOT
- 桩分发器实现常见 libc / 返回默认值
- 支持 hook 日志函数打印参数
"""
import sys
sys.path.insert(0, r"D:\qiling\qiling-master")

from collections import Counter
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from qiling import Qiling
from qiling.const import QL_VERBOSE
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

SO      = r"D:\qiling\work\libmxcore.so"
ROOTFS  = r"D:\qiling\rootfs\rootfs-master\arm64_android"

STUB_BASE   = 0x50000000
STUB_STRIDE = 0x40
HEAP_BASE   = 0x51000000
STACK_BASE  = 0x60000000
STACK_SIZE  = 0x100000
SENTINEL    = 0x6f000000


class Harness:
    def __init__(self, so, rootfs):
        self.ql = Qiling([so], rootfs=rootfs, verbose=QL_VERBOSE.DISABLED)
        self.base = self.ql.loader.load_address
        self.ql.mem.map(STUB_BASE, 0x40000)
        self.ql.mem.map(HEAP_BASE, 0x800000)
        self.ql.mem.map(STACK_BASE, STACK_SIZE)
        self.ql.mem.map(SENTINEL, 0x1000)
        self.heap_ptr = HEAP_BASE + 0x1000
        self.errno_ptr = HEAP_BASE
        self.sym_by_addr = {}
        self._apply_relocations(so)
        self.log_calls = []
        print(f"[harness] load_address={self.base:#x}")

    def _apply_relocations(self, so):
        """自己做完整重定位: RELATIVE + GLOB_DAT/ABS64 + JUMP_SLOT
        - 定义在库内的符号 -> base+st_value
        - 未定义(导入)      -> 桩地址
        """
        f = open(so, "rb")
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name('.dynsym')
        R_ABS64, R_GLOB_DAT, R_JUMP_SLOT, R_RELATIVE = 257, 1025, 1026, 1027
        stub_by_name = {}
        idx = 0
        n_rel = n_stub = n_def = 0
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            if sec.name not in ('.rela.dyn', '.rela.plt', '.rel.plt'):
                continue
            rela = sec.is_RELA()
            for rel in sec.iter_relocations():
                off = rel['r_offset']
                typ = rel['r_info_type']
                add = rel['r_addend'] if rela else 0
                if typ == R_RELATIVE:
                    self.ql.mem.write(self.base + off, self.ql.pack64(self.base + add))
                    n_rel += 1
                    continue
                sym = dynsym.get_symbol(rel['r_info_sym'])
                if sym['st_shndx'] == 'SHN_UNDEF' and sym.name:
                    if sym.name not in stub_by_name:
                        stub = STUB_BASE + idx * STUB_STRIDE
                        idx += 1
                        stub_by_name[sym.name] = stub
                        self.sym_by_addr[stub] = sym.name
                        if sym.name == 'pthread_once':
                            # 真 trampoline: 检查 once 标志 -> 首次跑 init(x1) -> w0=0
                            # ldr w9,[x0]; cbnz w9,skip; mov w9,#1; str w9,[x0];
                            # stp x29,x30,[sp,#-0x10]!; mov x29,sp; blr x1;
                            # ldp x29,x30,[sp],#0x10; skip: mov w0,#0; ret
                            self.ql.mem.write(stub, bytes.fromhex(
                                "090040b9"
                                "e9000035" "29008052" "090000b9" "fd7bbfa9" "fd030091" "20003fd6"
                                "fd7bc1a8" "e0031f2a" "c0035fd6"))
                        else:
                            self.ql.mem.write(stub, b"\xc0\x03\x5f\xd6")
                            self.ql.hook_address(self._make_dispatch(sym.name), stub)
                    val = stub_by_name[sym.name]
                    n_stub += 1
                elif sym.name and sym['st_shndx'] != 'SHN_UNDEF':
                    val = self.base + sym['st_value'] + add
                    n_def += 1
                else:
                    continue
                self.ql.mem.write(self.base + off, self.ql.pack64(val))
        f.close()
        print(f"[harness] reloc: relative={n_rel} defined={n_def} stubs={n_stub}")

    def _make_dispatch(self, name):
        def cb(ql):
            self._handle(ql, name)
        return cb

    def _malloc(self, size):
        p = self.heap_ptr
        self.heap_ptr += (size + 0xf) & ~0xf
        return p

    def _handle(self, ql, name):
        r = ql.arch.regs
        a0, a1, a2, a3 = r.x0, r.x1, r.x2, r.x3
        # 日志类: 打印
        if name in ('__android_log_print', '__android_log_write'):
            try:
                fmt = ql.mem.string(a2) if name.endswith('print') else ql.mem.string(a1)
                self.log_calls.append((name, fmt, [hex(x) for x in (a1, a2, a3)]))
                print(f"    [LOG] {name}: {fmt!r}  args={[hex(a0),hex(a1),hex(a2),hex(a3)]}")
            except Exception:
                pass
            r.x0 = 0; return
        if name == '__errno':
            r.x0 = self.errno_ptr; return
        if name in ('malloc', 'calloc'):
            n = a0 if name == 'malloc' else a0 * a1
            r.x0 = self._malloc(max(n, 16) if n else 16); return
        if name == 'realloc':
            r.x0 = self._malloc(a1 if a1 else 16); return
        if name == 'free':
            r.x0 = 0; return
        if name in ('pthread_mutex_lock','pthread_mutex_unlock','pthread_mutex_init',
                    'pthread_mutex_trylock','pthread_mutex_destroy','pthread_rwlock_rdlock',
                    'pthread_rwlock_wrlock','pthread_rwlock_unlock','pthread_rwlock_init',
                    'pthread_rwlock_destroy','pthread_cond_signal',
                    'pthread_cond_broadcast','pthread_cond_wait'):
            r.x0 = 0; return
        if name == 'pthread_once':
            # 首次执行 init 回调(x1), 之后跳过
            if a0 and a1 and ql.unpack32(ql.mem.read(a0, 4)) == 0:
                ql.mem.write(a0, ql.pack32(2))
                r.pc = a1            # 跳到 init; x30 仍是调用者返回地址
                return
            r.x0 = 0; return
        if name == '__cxa_guard_acquire':
            r.x0 = 1 if (a0 and ql.mem.read(a0, 1)[0] == 0) else 0
            return
        if name in ('__cxa_guard_release', '__cxa_guard_abort'):
            if a0: ql.mem.write(a0, b"\x01")
            r.x0 = 0; return
        if name == 'clock_gettime':
            r.x0 = 0; return
        if name == 'gettimeofday':
            r.x0 = 0; return
        if name in ('send', 'write', 'sendto'):
            r.x0 = a2; return       # 假装写了 len
        if name in ('recv', 'recvfrom', 'read'):
            r.x0 = 0; return        # 无数据
        if name == 'socket':
            r.x0 = 3; return
        if name in ('connect', 'listen', 'bind'):
            r.x0 = 0; return
        # 默认 0
        r.x0 = 0

    def call(self, vaddr, args, max_insn=20000, timeout_us=8_000_000):
        ql = self.ql
        regs = ql.arch.regs
        # 清寄存器
        for i in range(31):
            try: setattr(regs, f'x{i}', 0)
            except Exception: pass
        for i, a in enumerate(args[:8]):
            setattr(regs, f'x{i}', a & 0xFFFFFFFFFFFFFFFF)
        regs.sp = STACK_BASE + STACK_SIZE - 0x1000
        regs.x30 = SENTINEL
        return ql.emu_start(self.base + vaddr, SENTINEL, timeout=timeout_us, count=max_insn)


if __name__ == "__main__":
    h = Harness(SO, ROOTFS)
    ql = h.ql

    # --- hook 内部日志函数 sub_44DA84: 打印 fmt 后直接返回 ---
    def on_log(ql):
        r = ql.arch.regs
        try:
            fmt = ql.mem.string(r.x1)
        except Exception:
            fmt = "?"
        print(f"    [内部日志] x0={r.x0:#x} fmt={fmt!r}")
        r.pc = r.x30
    ql.hook_address(on_log, h.base + 0x44DA84)

    # --- hook write 原语 sub_489DBC: 返回成功 ---
    REAL_WRITE = True
    def on_write(ql):
        r = ql.arch.regs
        print(f"    [write原语 sub_489DBC] x0={r.x0:#x} x1={r.x1:#x} x2={r.x2:#x}")
        r.x0 = r.x2 if r.x2 < 0x10000 else 16
        r.pc = r.x30
    if not REAL_WRITE:
        ql.hook_address(on_write, h.base + 0x489DBC)
    else:
        # 观察真实 sub_489DBC 的入口和调用
        def on_489dbc_enter(ql):
            print(f"    [真实 sub_489DBC 进入] x0={ql.arch.regs.x0:#x} x1={ql.arch.regs.x1:#x} x2={ql.arch.regs.x2:#x}")
        ql.hook_address(on_489dbc_enter, h.base + 0x489DBC)

    # --- hook 第一层 sub_500E2C 的入口, 只观察 ---
    def on_500e2c(ql):
        print(f"    [进入 sub_500E2C] x0={ql.arch.regs.x0:#x}")
    ql.hook_address(on_500e2c, h.base + 0x500E2C)

    # --- BL 调用追踪器 ---
    bl_counter = Counter()
    bl_seq = []
    def on_code(ql, addr, size):
        try:
            code = ql.mem.read(addr, 4)
        except Exception:
            return
        for insn in MD.disasm(bytes(code), addr):
            if insn.mnemonic == 'bl' and insn.op_str.startswith('#'):
                toff = int(insn.op_str[1:], 16) - h.base
                bl_counter[toff] += 1
                if len(bl_seq) < 100:
                    bl_seq.append(toff)
            break
    ql.hook_code(on_code)

    print("\n[*] 直接调用 sub_46AA74 ...")
    # 合成上下文: ctx + idx*0x28 +0x2A0 -> obj ; obj+8 -> inner
    ctx   = HEAP_BASE + 0x70000
    obj   = HEAP_BASE + 0x80000
    inner = HEAP_BASE + 0x90000
    buf   = HEAP_BASE + 0xA0000
    out   = HEAP_BASE + 0xB0000
    ql.mem.write(ctx + 0x2A0, ql.pack64(obj))
    ql.mem.write(obj + 8,      ql.pack64(inner))
    ql.mem.write(buf, b"HELLO_SSL_WRITE_TEST")
    try:
        h.call(0x46AA74, [ctx, 0, buf, 16, out])
        print(f"[+] 返回, w0={ql.arch.regs.w0:#x}  pc={ql.arch.regs.pc:#x}")
    except Exception as e:
        print(f"[!] {type(e).__name__}: {e}")
        print(f"[!] pc={ql.arch.regs.pc:#x}")

    print("\n[*] BL 调用统计 (目标函数偏移):")
    for off, cnt in bl_counter.most_common(40):
        print(f"    +{off:#x}: {cnt} 次")
    print("\n[*] 前 100 个 BL 序列:")
    print("    " + " ".join(f"+{o:#x}" for o in bl_seq))
