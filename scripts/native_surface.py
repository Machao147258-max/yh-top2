"""Extract native method declarations + class distribution from dex.
Writes result into the 异环 work folder. Logging fully silenced."""
import zipfile, logging, os

logging.getLogger("androguard").setLevel(logging.CRITICAL)
logging.getLogger("androguard.core.dex").setLevel(logging.CRITICAL)
for name in list(logging.root.manager.loggerDict):
    if "androguard" in name:
        logging.getLogger(name).setLevel(logging.CRITICAL)
logging.disable(logging.CRITICAL)

from androguard.core.dex import DEX
from collections import Counter

APK = r"D:\dwonload\yh_gw_20260702.apk"
WORK = r"C:\Users\20751\Desktop\异环"
OUT = os.path.join(WORK, "native_surface_report.txt")
z = zipfile.ZipFile(APK)

natives = []
pkg_tops = Counter()
dex_classes = {}

for dexname in ["classes.dex","classes2.dex","classes3.dex","classes4.dex","classes5.dex"]:
    d = DEX(z.read(dexname))
    cnt = 0
    for cls in d.get_classes():
        cnt += 1
        cn = cls.get_name()
        parts = cn[1:].split("/")
        pkg_tops[parts[0]] += 1
        for m in cls.get_methods():
            if m.get_access_flags() & 0x100:  # ACC_NATIVE
                natives.append((cn, m.get_name()))
    dex_classes[dexname] = cnt

lines = []
lines.append("=== dex class counts ===")
for n, c in dex_classes.items():
    lines.append("  %-12s %d" % (n, c))
lines.append("")
lines.append("== native method total: %d ==" % len(natives))
lines.append("")
lines.append("== top packages (all dex) ==")
for p, c in pkg_tops.most_common(30):
    lines.append("  %6d  %s" % (c, p))
lines.append("")
lines.append("== native methods grouped by class (all) ==")
byclass = Counter()
for cn, mn in natives:
    byclass[cn] += 1
for cn, c in byclass.most_common():
    lines.append("  %4d  %s" % (c, cn))
lines.append("")
lines.append("== native method name top 80 ==")
names = Counter(mn for _, mn in natives)
for mn, c in names.most_common(80):
    lines.append("  %4d  %s" % (c, mn))

open(OUT, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("written", OUT)
print("lines", len(lines))