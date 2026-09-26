#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA 脚本：搜索 libUnreal.so 中可能的 AES-256 密钥
AES-256 密钥是 32 字节高熵数据
"""

import idaapi
import idautils
import idc
import ida_bytes
import ida_name
import struct
import math

def calculate_entropy(data):
    """计算数据熵"""
    if not data:
        return 0.0
    
    # 统计字节频率
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    # 计算熵
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return entropy

def find_aes_keys():
    """搜索可能的 AES-256 密钥（32 字节高熵数据）"""
    
    print("=== 搜索可能的 AES-256 密钥 ===\n")
    
    # 获取所有段
    segments = []
    for seg in idautils.Segments():
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        seg_name = idc.get_segm_name(seg)
        seg_perm = idc.get_segm_attr(seg, idc.SEGATTR_PERM)
        
        # 只搜索只读段（.rodata）和可执行段
        if seg_perm & 0x4:  # 可读
            segments.append((seg_start, seg_end, seg_name))
    
    print(f"找到 {len(segments)} 个可读段\n")
    
    candidates = []
    
    for seg_start, seg_end, seg_name in segments:
        print(f"扫描段: {seg_name} (0x{seg_start:x} - 0x{seg_end:x})")
        
        # 每 4 字节对齐扫描
        addr = seg_start
        while addr + 32 <= seg_end:
            # 读取 32 字节
            data = ida_bytes.get_bytes(addr, 32)
            
            if data and len(data) == 32:
                # 计算熵
                entropy = calculate_entropy(data)
                
                # AES 密钥通常熵 > 7.0（32 字节最大熵是 8.0）
                if entropy > 7.0:
                    # 检查是否是全 0 或全相同字节
                    if len(set(data)) > 10:  # 至少 10 个不同字节
                        candidates.append({
                            'addr': addr,
                            'entropy': entropy,
                            'data': data,
                            'segment': seg_name
                        })
            
            addr += 4
    
    print(f"\n找到 {len(candidates)} 个高熵 32 字节块\n")
    
    # 按熵排序，取前 20 个
    candidates.sort(key=lambda x: x['entropy'], reverse=True)
    
    print("=== 前 20 个候选密钥 ===\n")
    for i, cand in enumerate(candidates[:20]):
        addr = cand['addr']
        entropy = cand['entropy']
        data = cand['data']
        seg = cand['segment']
        
        # 显示为十六进制
        hex_str = ' '.join(f'{b:02x}' for b in data)
        
        print(f"#{i+1} 地址: 0x{addr:x}  段: {seg}  熵: {entropy:.3f}")
        print(f"    数据: {hex_str}")
        
        # 查找引用这个地址的代码
        xrefs = list(idautils.XrefsTo(addr))
        if xrefs:
            print(f"    引用: {len(xrefs)} 处")
            for xref in xrefs[:3]:
                func = idaapi.get_func(xref.frm)
                if func:
                    func_name = ida_name.get_name(func.start_ea)
                    print(f"      - 函数: {func_name} @ 0x{func.start_ea:x}")
        else:
            print(f"    引用: 无")
        print()
    
    return candidates

# 执行搜索
candidates = find_aes_keys()

# 保存结果
output_file = r'C:\Users\20751\Desktop\异环\reports\ida_aes_key_candidates.txt'
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(f"找到 {len(candidates)} 个高熵 32 字节块\n\n")
    
    candidates.sort(key=lambda x: x['entropy'], reverse=True)
    
    for i, cand in enumerate(candidates[:50]):
        addr = cand['addr']
        entropy = cand['entropy']
        data = cand['data']
        seg = cand['segment']
        
        hex_str = ' '.join(f'{b:02x}' for b in data)
        
        f.write(f"#{i+1} 地址: 0x{addr:x}  段: {seg}  熵: {entropy:.3f}\n")
        f.write(f"    数据: {hex_str}\n")
        
        xrefs = list(idautils.XrefsTo(addr))
        if xrefs:
            f.write(f"    引用: {len(xrefs)} 处\n")
            for xref in xrefs[:5]:
                func = idaapi.get_func(xref.frm)
                if func:
                    func_name = ida_name.get_name(func.start_ea)
                    f.write(f"      - 函数: {func_name} @ 0x{func.start_ea:x}\n")
        else:
            f.write(f"    引用: 无\n")
        f.write("\n")

print(f"\n结果已保存到: {output_file}")
