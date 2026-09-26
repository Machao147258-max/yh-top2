#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
直接搜索 libUnreal.so 中可能的 AES-256 密钥
AES-256 密钥是 32 字节高熵数据（熵 > 7.0）
"""

import struct
import math
import sys

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

def parse_elf_segments(data):
    """解析 ELF 段表"""
    # ELF header
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]
    
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type == 1:  # PT_LOAD
            p_offset = struct.unpack_from('<Q', data, off + 8)[0]
            p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
            p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
            p_flags = struct.unpack_from('<I', data, off + 4)[0]
            
            segments.append({
                'offset': p_offset,
                'vaddr': p_vaddr,
                'size': p_filesz,
                'flags': p_flags
            })
    
    return segments

def find_aes_keys(so_path):
    """搜索可能的 AES-256 密钥"""
    
    print(f"=== 分析 {so_path} ===\n")
    
    with open(so_path, 'rb') as f:
        data = f.read()
    
    print(f"文件大小: {len(data) / 1024 / 1024:.2f} MB\n")
    
    # 解析 ELF 段
    segments = parse_elf_segments(data)
    print(f"找到 {len(segments)} 个 LOAD 段:\n")
    
    for i, seg in enumerate(segments):
        flags_str = ''
        if seg['flags'] & 4: flags_str += 'R'
        if seg['flags'] & 2: flags_str += 'W'
        if seg['flags'] & 1: flags_str += 'X'
        
        print(f"  #{i+1} offset=0x{seg['offset']:x}  vaddr=0x{seg['vaddr']:x}  "
              f"size=0x{seg['size']:x}  flags={flags_str}")
    
    print()
    
    # 搜索高熵 32 字节块
    candidates = []
    
    # 只搜索可读段（R 标志）
    for seg in segments:
        if seg['flags'] & 0x4:  # 可读
            print(f"扫描段: offset=0x{seg['offset']:x} - 0x{seg['offset']+seg['size']:x}")
            
            # 每 4 字节对齐扫描
            offset = seg['offset']
            end_offset = seg['offset'] + seg['size']
            
            while offset + 32 <= end_offset:
                chunk = data[offset:offset+32]
                
                # 计算熵
                entropy = calculate_entropy(chunk)
                
                # AES 密钥通常熵 > 7.0
                if entropy > 7.0:
                    # 检查是否是全 0 或全相同字节
                    if len(set(chunk)) > 10:  # 至少 10 个不同字节
                        vaddr = seg['vaddr'] + (offset - seg['offset'])
                        candidates.append({
                            'offset': offset,
                            'vaddr': vaddr,
                            'entropy': entropy,
                            'data': chunk
                        })
                
                offset += 4
    
    print(f"\n找到 {len(candidates)} 个高熵 32 字节块\n")
    
    # 按熵排序
    candidates.sort(key=lambda x: x['entropy'], reverse=True)
    
    # 显示前 20 个
    print("=== 前 20 个候选密钥 ===\n")
    for i, cand in enumerate(candidates[:20]):
        offset = cand['offset']
        vaddr = cand['vaddr']
        entropy = cand['entropy']
        chunk = cand['data']
        
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        
        print(f"#{i+1} offset=0x{offset:x}  vaddr=0x{vaddr:x}  熵={entropy:.3f}")
        print(f"    {hex_str}")
        print()
    
    # 保存结果
    output_file = r'C:\Users\20751\Desktop\异环\reports\aes_key_candidates.txt'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"找到 {len(candidates)} 个高熵 32 字节块\n\n")
        
        for i, cand in enumerate(candidates[:100]):
            offset = cand['offset']
            vaddr = cand['vaddr']
            entropy = cand['entropy']
            chunk = cand['data']
            
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            
            f.write(f"#{i+1} offset=0x{offset:x}  vaddr=0x{vaddr:x}  熵={entropy:.3f}\n")
            f.write(f"    {hex_str}\n\n")
    
    print(f"结果已保存到: {output_file}")
    
    return candidates

if __name__ == '__main__':
    so_path = r'C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so'
    find_aes_keys(so_path)
