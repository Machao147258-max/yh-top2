"""Find laohu/onesdk login entry classes to decompile with jadx."""
import zipfile, os
from collections import defaultdict
from androguard.core.dex import DEX

APK = r"D:\dwonload\yh_gw_20260702.apk"
z = zipfile.ZipFile(APK)

needles = ["laohu","onesdk","passport","Login","login"]
candidates = defaultdict(int)

for dexname in ["classes.dex","classes2.dex","classes3.dex","classes4.dex","classes5.dex"]:
    d = DEX(z.read(dexname))
    for cls in d.get_classes():
        cn = cls.get_name()  # Lpkg/...;
        low = cn.lower()
        if "laohu" in low or "passport" in low:
            candidates[cn] += 1

for cn in sorted(candidates, key=lambda x: -candidates[x]):
    print(cn, candidates[cn])