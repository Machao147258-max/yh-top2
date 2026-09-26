# -*- coding: utf-8 -*-
import zipfile, glob, os
jar=r"C:\Users\20751\.m2\repository\com\github\zhkl0228\unidbg-api\0.9.10-SNAPSHOT\unidbg-api-0.9.10-SNAPSHOT.jar"
needle=b"debugger break at"
z=zipfile.ZipFile(jar)
for n in z.namelist():
    if n.endswith(".class"):
        d=z.read(n)
        if needle in d:
            print("HIT:", n)
# 也扫所有 unidbg jar
print("--- 全 unidbg jar ---")
for jar in glob.glob(r"C:\Users\20751\.m2\repository\com\github\zhkl0228\**\*.jar", recursive=True):
    try:
        z=zipfile.ZipFile(jar)
        for n in z.namelist():
            if n.endswith(".class"):
                if needle in z.read(n):
                    print(os.path.basename(jar), "::", n)
    except: pass
