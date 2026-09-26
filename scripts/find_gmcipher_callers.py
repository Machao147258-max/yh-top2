"""Robust xref for GmCipher: use androguard xref + string scan. Logs to file."""
import zipfile, os
from androguard.core.dex import DEX

APK = r"D:\dwonload\yh_gw_20260702.apk"
OUT = r"C:\Users\20751\Desktop\异环\reports\05_GmCipher_callers.txt"
z = zipfile.ZipFile(APK)

TARGET = "Lcom/kycgm/GmCipher;"
TARGET_S = "GmCipher"

from collections import defaultdict
callers = defaultdict(list)   # caller_class -> set of method names
string_hits = defaultdict(int)  # class -> count of "GmCipher" strings

for dexname in ["classes.dex","classes2.dex","classes3.dex","classes4.dex","classes5.dex"]:
    d = DEX(z.read(dexname))
    for cls in d.get_classes():
        cn = cls.get_name()
        # scan class strings
        try:
            for s in cls.get_string_refs():
                if TARGET_S in (s or ""):
                    string_hits[cn] += 1
        except Exception:
            pass
        for m in cls.get_methods():
            if m.get_access_flags() & 0x100:
                continue
            code = m.get_code()
            if code is None:
                continue
            try:
                bc = code.get_bc()
            except Exception:
                continue
            for ins in bc.get_instructions():
                op = ins.get_name()
                if op.startswith("invoke-") or op in ("sget-object","iput-object","new-instance","const-class","const-string","const/high16","const-string/jumbo"):
                    try:
                        refs = ins.get_operand_value()
                    except Exception:
                        continue
                    # refs may be tuple/list
                    if isinstance(refs, (tuple, list)):
                        vals = [str(x) for x in refs]
                    else:
                        vals = [str(refs)]
                    if any(TARGET in v or TARGET_S in v for v in vals):
                        callers[cn].add(m.get_name())

lines = []
lines.append("== string 'GmCipher' occurrences by class ==")
for cn, c in sorted(string_hits.items(), key=lambda x:-x[1]):
    lines.append("  %4d  %s" % (c, cn))
lines.append("")
lines.append("== classes/methods referencing GmCipher type ==")
if not callers:
    lines.append("  (no direct type refs found — likely loaded via System.loadLibrary + reflection)")
for cn, methods in sorted(callers.items(), key=lambda x:-len(x[1])):
    lines.append("class %s" % cn)
    for mn in sorted(methods):
        lines.append("    %s" % mn)

open(OUT,"w",encoding="utf-8").write("\n".join(lines)+"\n")
print("wrote", OUT)
print("string_hits classes:", len(string_hits))
print("type-ref caller classes:", len(callers))