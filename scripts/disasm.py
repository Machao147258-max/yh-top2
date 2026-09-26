#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编 libUnreal.so 指定地址范围的 ARM64 代码"""

import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def disasm(so_path, start, size, label=""):
    with open(so_path, 'rb') as f:
        f.seek(start)
        code = f.read(size)
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    
    print(f"\n=== {label} @ 0x{start:x}, {size} bytes ===")
    for ins in md.disasm(code, start):
        # 标注 adrp 地址
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

if __name__ == '__main__':
    so_path = sys.argv[1]
    start = int(sys.argv[2], 16)
    size = int(sys.argv[3], 16)
    label = sys.argv[4] if len(sys.argv) > 4 else ""
    disasm(so_path, start, size, label)
