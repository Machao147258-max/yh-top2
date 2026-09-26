"""Search dex strings for kycgm / sm4 / sm2 / loadLibrary references."""
import zipfile, os
from collections import defaultdict
from androguard.core.dex import DEX

APK = r"D:\dwonload\yh_gw_20260702.apk"
OUT = r"C:\Users\20751\Desktop\异环\reports\05_kycgm_strings.txt"
z = zipfile.ZipFile(APK)

needles = ["kycgm","sm4","sm2","SM4","SM2","GmCipher","loadLibrary","libkycgm"]
hits = defaultdict(list)  # class -> [string]

for dexname in ["classes.dex","classes2.dex","classes3.dex","classes4.dex","classes5.dex"]:
    d = DEX(z.read(dexname))
    for cls in d.get_classes():
        cn = cls.get_name()
        try:
            strs = list(cls.get_string_refs())
        except Exception:
            strs = []
        for s in strs:
            if not s:
                continue
            low = s.lower()
            for nd in needles:
                if nd in low:
                    hits[cn].append(s)

lines = []
for cn, ss in sorted(hits.items(), key=lambda x: -len(x[1])):
    lines.append("class %s" % cn)
    for s in sorted(set(ss)):
        lines.append("    %r" % s[:160])
open(OUT,"w",encoding="utf-8").write("\n".join(lines)+"\n")
print("wrote", OUT, "classes:", len(hits))