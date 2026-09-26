"""Disassemble key self-developed native classes: mxsdk Native + kycgm GmCipher.
Writes smali-ish output to 异环/reports/."""
import zipfile, os, sys
from androguard.core.dex import DEX

APK = r"D:\dwonload\yh_gw_20260702.apk"
OUT = r"C:\Users\20751\Desktop\异环\reports"
z = zipfile.ZipFile(APK)

targets = {
    "Lcom/sdk/mxsdk/im/core/Native;": "04_mxsdk_Native_methods.txt",
    "Lcom/kycgm/GmCipher;": "04_GmCipher_methods.txt",
    "Lcom/wpsdk/one/global/bridge/OneGlobalJNI;": "04_OneGlobalJNI_methods.txt",
}

result = {}
for dexname in ["classes.dex","classes2.dex","classes3.dex","classes4.dex","classes5.dex"]:
    d = DEX(z.read(dexname))
    for cls in d.get_classes():
        cn = cls.get_name()
        if cn not in targets:
            continue
        lines = result.setdefault(cn, [])
        if not lines:
            lines.append("class %s  (dex %s)" % (cn, dexname))
            lines.append("super: %s" % (cls.get_superclassname() or "?"))
            try:
                lines.append("access: 0x%x" % cls.get_access_flags())
            except Exception:
                pass
        for m in cls.get_methods():
            acc = m.get_access_flags()
            flags = []
            if acc & 0x100: flags.append("native")
            if acc & 0x1: flags.append("public")
            if acc & 0x2: flags.append("private")
            if acc & 0x4: flags.append("protected")
            if acc & 0x8: flags.append("static")
            if acc & 0x10000: flags.append("synthetic")
            try:
                proto = m.get_prototype().get_buffer() if hasattr(m.get_prototype(),"get_buffer") else str(m.get_prototype())
            except Exception:
                proto = "?"
            lines.append("    %s %s(%s)  [%s]" % (
                m.get_name(),
                "(" + ",".join(flags) + ")",
                proto,
                dexname,
            ))

for cn, path in targets.items():
    lines = result.get(cn)
    if not lines:
        with open(os.path.join(OUT, path), "w", encoding="utf-8") as f:
            f.write("class not found\n")
        print("NOT FOUND", cn)
        continue
    with open(os.path.join(OUT, path), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote", path, "methods:", len(lines)-3)

print("done")