#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDA 脚本：搜索 IoStore/Pak 相关字符串并找引用函数"""

import idaapi
import idautils
import idc
import ida_bytes
import ida_name

def find_iostore_refs():
    """找 IoStore/Pak 相关字符串和引用"""
    
    # 搜索关键词
    keywords = [b'IoStore', b'Pak', b'pakchunk', b'.utoc', b'.ucas', b'FAES', b'Crypto']
    
    results = []
    
    for keyword in keywords:
        # 搜索字符串
        addr = idc.BADADDR
        while True:
            addr = ida_bytes.find_binary(addr + 1, idc.BADADDR, keyword, 16, idc.SEARCH_DOWN | idc.SEARCH_CASE)
            if addr == idc.BADADDR:
                break
            
            # 读取完整字符串
            str_val = ida_bytes.get_strlit_contents(addr, -1, idc.STRTYPE_C)
            if str_val:
                str_val = str_val.decode('utf-8', errors='replace')
                
                # 找引用这个字符串的代码
                xrefs = list(idautils.XrefsTo(addr))
                if xrefs:
                    for xref in xrefs:
                        func = idaapi.get_func(xref.frm)
                        if func:
                            func_name = ida_name.get_name(func.start_ea)
                            results.append({
                                'string': str_val,
                                'string_addr': addr,
                                'ref_addr': xref.frm,
                                'func_addr': func.start_ea,
                                'func_name': func_name
                            })
    
    # 输出结果
    print(f"\n=== 找到 {len(results)} 个引用 ===\n")
    
    # 按函数分组
    funcs = {}
    for r in results:
        key = r['func_addr']
        if key not in funcs:
            funcs[key] = {
                'func_name': r['func_name'],
                'func_addr': r['func_addr'],
                'strings': []
            }
        funcs[key]['strings'].append(r['string'])
    
    # 打印
    for func_addr, info in sorted(funcs.items()):
        print(f"函数: {info['func_name']} @ 0x{func_addr:x}")
        for s in info['strings'][:5]:  # 只显示前5个
            print(f"  - {s}")
        print()
    
    return results

# 执行
results = find_iostore_refs()

# 保存到文件
with open(r'C:\Users\20751\Desktop\异环\reports\ida_iostore_refs.txt', 'w', encoding='utf-8') as f:
    f.write(f"找到 {len(results)} 个 IoStore/Pak 相关引用\n\n")
    
    funcs = {}
    for r in results:
        key = r['func_addr']
        if key not in funcs:
            funcs[key] = {'func_name': r['func_name'], 'func_addr': r['func_addr'], 'strings': []}
        funcs[key]['strings'].append(r['string'])
    
    for func_addr, info in sorted(funcs.items()):
        f.write(f"函数: {info['func_name']} @ 0x{func_addr:x}\n")
        for s in info['strings']:
            f.write(f"  - {s}\n")
        f.write("\n")

print(f"\n结果已保存到 ida_iostore_refs.txt")
