#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 ELF 符号表（静态符号 + 动态符号）"""

import struct
import sys

def parse_elf_symbols(so_path):
    with open(so_path, 'rb') as f:
        data = f.read()
    
    # ELF header
    e_ident = data[:16]
    if e_ident[:4] != b'\x7fELF':
        print("Not an ELF file")
        return
    
    ei_class = e_ident[4]  # 1=32bit, 2=64bit
    ei_data = e_ident[5]   # 1=little, 2=big
    
    if ei_class == 2:  # 64-bit
        e_shoff = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx = struct.unpack_from('<H', data, 62)[0]
    else:  # 32-bit
        e_shoff = struct.unpack_from('<I', data, 32)[0]
        e_shentsize = struct.unpack_from('<H', data, 46)[0]
        e_shnum = struct.unpack_from('<H', data, 48)[0]
        e_shstrndx = struct.unpack_from('<H', data, 50)[0]
    
    # Parse section headers
    sections = []
    for i in range(e_shnum):
        offset = e_shoff + i * e_shentsize
        if ei_class == 2:
            sh_name = struct.unpack_from('<I', data, offset)[0]
            sh_type = struct.unpack_from('<I', data, offset + 4)[0]
            sh_offset = struct.unpack_from('<Q', data, offset + 24)[0]
            sh_size = struct.unpack_from('<Q', data, offset + 32)[0]
            sh_link = struct.unpack_from('<I', data, offset + 40)[0]
            sh_entsize = struct.unpack_from('<Q', data, offset + 56)[0]
        else:
            sh_name = struct.unpack_from('<I', data, offset)[0]
            sh_type = struct.unpack_from('<I', data, offset + 4)[0]
            sh_offset = struct.unpack_from('<I', data, offset + 16)[0]
            sh_size = struct.unpack_from('<I', data, offset + 20)[0]
            sh_link = struct.unpack_from('<I', data, offset + 24)[0]
            sh_entsize = struct.unpack_from('<I', data, offset + 36)[0]
        
        sections.append({
            'name_offset': sh_name,
            'type': sh_type,
            'offset': sh_offset,
            'size': sh_size,
            'link': sh_link,
            'entsize': sh_entsize
        })
    
    # Get string table
    strtab = sections[e_shstrndx]
    strtab_data = data[strtab['offset']:strtab['offset']+strtab['size']]
    
    def get_string(offset):
        end = strtab_data.find(b'\x00', offset)
        return strtab_data[offset:end].decode('utf-8', errors='ignore')
    
    # Find symbol tables (SHT_SYMTAB=2, SHT_DYNSYM=11)
    for sec in sections:
        if sec['type'] not in [2, 11]:  # SYMTAB or DYNSYM
            continue
        
        sec_name = get_string(sec['name_offset'])
        symtab_offset = sec['offset']
        symtab_size = sec['size']
        strtab_sec = sections[sec['link']]
        sym_strtab = data[strtab_sec['offset']:strtab_sec['offset']+strtab_sec['size']]
        
        def get_sym_string(offset):
            end = sym_strtab.find(b'\x00', offset)
            return sym_strtab[offset:end].decode('utf-8', errors='ignore')
        
        # Parse symbols
        if ei_class == 2:  # 64-bit
            entry_size = 24
        else:  # 32-bit
            entry_size = 16
        
        num_symbols = symtab_size // entry_size
        
        print(f"\n=== {sec_name} ({num_symbols} symbols) ===")
        
        for i in range(num_symbols):
            sym_offset = symtab_offset + i * entry_size
            
            if ei_class == 2:  # 64-bit
                st_name = struct.unpack_from('<I', data, sym_offset)[0]
                st_info = data[sym_offset + 4]
                st_other = data[sym_offset + 5]
                st_shndx = struct.unpack_from('<H', data, sym_offset + 6)[0]
                st_value = struct.unpack_from('<Q', data, sym_offset + 8)[0]
                st_size = struct.unpack_from('<Q', data, sym_offset + 16)[0]
            else:  # 32-bit
                st_name = struct.unpack_from('<I', data, sym_offset)[0]
                st_value = struct.unpack_from('<I', data, sym_offset + 4)[0]
                st_size = struct.unpack_from('<I', data, sym_offset + 8)[0]
                st_info = data[sym_offset + 12]
                st_other = data[sym_offset + 13]
                st_shndx = struct.unpack_from('<H', data, sym_offset + 14)[0]
            
            name = get_sym_string(st_name)
            st_bind = st_info >> 4
            st_type = st_info & 0xf
            
            # Filter interesting symbols
            if any(kw in name for kw in ['JNI_OnLoad', 'Java_', 'RegisterNatives', 'GmCipher', 'IoStore', 'FAES']):
                bind_str = 'LOCAL' if st_bind == 0 else 'GLOBAL' if st_bind == 1 else 'WEAK'
                type_str = 'NOTYPE' if st_type == 0 else 'FUNC' if st_type == 2 else 'OBJECT' if st_type == 1 else str(st_type)
                print(f"  0x{st_value:016x}  {name:60s}  size={st_size:8d}  {bind_str:8s}  {type_str:8s}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python elf_sym.py <so_path>")
        sys.exit(1)
    
    parse_elf_symbols(sys.argv[1])
