"""Decompile selected classes to readable smali-ish via androguard.
Logging silenced by wrapping output capture."""
import zipfile, os, sys, io
from contextlib import redirect_stderr, redirect_stdout

buf = io.StringIO()
with redirect_stderr(buf), redirect_stdout(buf):
    from androguard.core.dex import DEX

APK = r"D:\dwonload\yh_gw_20260702.apk"
OUT = r"C:\Users\20751\Desktop\异环\reports"
z = zipfile.ZipFile(APK)

# class -> output file
targets = {
    "Lcom/kycgm/GmCipher;": "07_GmCipher_decompiled.txt",
    "Lcom/sdk/mxsdk/im/core/Native;": "07_mxsdk_decompiled.txt",
    "Lcom/wpsdk/one/global/bridge/OneGlobalJNI;": "07_OneGlobalJNI_decompiled.txt",
}

found = {}

for dexname in ["classes.dex","classes2.dex","classes3.dex","classes4.dex","classes5.dex"]:
    with redirect_stderr(buf), redirect_stdout(buf):
        d = DEX(z.read(dexname))
    for cls in d.get_classes():
        cn = cls.get_name()
        if cn not in targets:
            continue
        if cn in found:
            continue
        lines = []
        lines.append(";; %s  (dex %s)" % (cn, dexname))
        lines.append(";; super=%s" % (cls.get_superclassname() or "?"))
        for m in cls.get_methods():
            acc = m.get_access_flags()
            tag = "native" if acc & 0x100 else ""
            lines.append(";; method %s %s" % (m.get_name(), tag))
            code = m.get_code()
            if code is None:
                lines.append("    ; (no code)")
                continue
            with redirect_stderr(buf), redirect_stdout(buf):
                try:
                    bc = code.get_bc()
                    dis = list(bc.get_instructions())
                except Exception as e:
                    lines.append("    ; disasm err %s" % e)
                    continue
            for ins in dis:
                try:
                    lines.append("    " + ins.get_output())
                except Exception:
                    lines.append("    " + ins.get_name())
            lines.append("")
        found[cn] = lines

for cn, path in targets.items():
    if cn in found:
        open(os.path.join(OUT, path), "w", encoding="utf-8").write("\n".join(found[cn]) + "\n")
        print("wrote", path, "lines", len(found[cn]))
    else:
        open(os.path.join(OUT, path), "w", encoding="utf-8").write("class not found\n")
        print("NOT FOUND", cn)

print("done")