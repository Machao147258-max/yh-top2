#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""搜 libUnreal.so 符号表里的 IoStore/Encryption/AES 相关符号"""

import struct
import sys

def parse_elf(so_path):
    with open(so_path, 'rb') as f:
        data = f.read()
    
    e_ident = data[:16]
    if e_ident[:4] != b'\x7fELF':
        print("Not ELF"); return None
    
    ei_class = e_ident[4]
    if ei_class == 2:  # 64-bit
        e_shoff = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx = struct.unpack_from('<H', data, 62)[0]
    else:
        print("32-bit not supported"); return None
    
    sections = []
    for i in range(e_shnum):
        offset = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from('<I', data, offset)[0]
        sh_type = struct.unpack_from('<I', data, offset + 4)[0]
        sh_offset = struct.unpack_from('<Q', data, offset + 24)[0]
        sh_size = struct.unpack_from('<Q', data, offset + 32)[0]
        sh_link = struct.unpack_from('<I', data, offset + 40)[0]
        sh_entsize = struct.unpack_from('<Q', data, offset + 56)[0]
        sections.append({'name_offset': sh_name, 'type': sh_type, 'offset': sh_offset, 'size': sh_size, 'link': sh_link, 'entsize': sh_entsize})
    
    strtab = sections[e_shstrndx]
    strtab_data = data[strtab['offset']:strtab['offset']+strtab['size']]
    
    def get_string(offset):
        end = strtab_data.find(b'\x00', offset)
        return strtab_data[offset:end].decode('utf-8', errors='ignore')
    
    return data, sections, get_string

def search_symbols(so_path, keywords):
    r = parse_elf(so_path)
    if not r: return
    data, sections, get_string = r
    
    for sec in sections:
        if sec['type'] not in [2, 11]:
            continue
        sec_name = get_string(sec['name_offset'])
        symtab_offset = sec['offset']
        symtab_size = sec['size']
        strtab_sec = sections[sec['link']]
        sym_strtab = data[strtab_sec['offset']:strtab_sec['offset']+strtab_sec['size']]
        
        def get_sym_string(offset):
            end = sym_strtab.find(b'\x00', offset)
            return sym_strtab[offset:end].decode('utf-8', errors='ignore')
        
        entry_size = 24
        num_symbols = symtab_size // entry_size
        
        print(f"\n=== {sec_name} ({num_symbols} symbols) ===")
        
        hits = []
        for i in range(num_symbols):
            sym_offset = symtab_offset + i * entry_size
            st_name = struct.unpack_from('<I', data, sym_offset)[0]
            st_info = data[sym_offset + 4]
            st_value = struct.unpack_from('<Q', data, sym_offset + 8)[0]
            st_size = struct.unpack_from('<Q', data, sym_offset + 16)[0]
            
            name = get_sym_string(st_name)
            st_bind = st_info >> 4
            st_type = st_info & 0xf
            
            # 搜关键字
            if any(kw in name.lower() for kw in keywords):
                bind_str = 'LOCAL' if st_bind == 0 else 'GLOBAL' if st_bind == 1 else 'WEAK'
                type_str = 'NOTYPE' if st_type == 0 else 'FUNC' if st_type == 2 else 'OBJECT' if st_type == 1 else str(st_type)
                hits.append((st_value, name, st_size, bind_str, type_str))
        
        print(f"  找到 {len(hits)} 个匹配符号:")
        for val, name, size, bind, typ in hits[:50]:
            print(f"    0x{val:016x}  {name:80s}  size={size:8d}  {bind:8s}  {typ:8s}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python find_iostore_symbols.py <so_path>")
        sys.exit(1)
    
    keywords = ['iostore', 'encrypt', 'aes', 'crypto', 'key', 'pak', 'container']
    search_symbols(sys.argv[1], keywords)
