# -*- coding: utf-8 -*-
"""libthemis: 导入API + JNI导出 + 反转串关键词。"""
import os
from elftools.elf.elffile import ELFFile
W=r"C:\Users\20751\Desktop\异环"
for name in ("libthemis.so","libsecsdk.so"):
    p=os.path.join(W,"unpacked","so",name)
    f=open(p,"rb"); elf=ELFFile(f)
    dyn=elf.get_section_by_name('.dynsym')
    imports=[]; exports=[]
    for s in dyn.iter_symbols():
        if not s.name: continue
        if s['st_shndx']=='SHN_UNDEF': imports.append(s.name)
        else: exports.append(s.name)
    print(f"\n===== {name} =====")
    print(f"  导入 {len(imports)}: {sorted(set(imports))}")
    jni=[e for e in exports if e.startswith('Java_') or e in ('JNI_OnLoad',)]
    print(f"  JNI导出 {len(jni)}: {jni}")
    f.close()
