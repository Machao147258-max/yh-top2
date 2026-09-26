"""libkycgm.so scanner: exports, JNI_OnLoad, strings."""
import lief, re

p = r"C:\Users\20751\Desktop\异环\unpacked\so\libkycgm.so"
b = lief.parse(p)
print("=== FILE %s ===" % p.split('/')[-1])
print("size", b.size, "arch", b.arch, "machine", b.machine)

print("\n=== EXPORTED SYMBOLS ===")
try:
    n = len(list(b.exported_symbols))
    print("count", n)
    for i, s in enumerate(b.exported_symbols):
        if i < 100:
            print("  %-48s 0x%x" % (s.name, s.value))
except Exception as e:
    print("err", e)

print("\n=== EXPORTED (all names) ===")
try:
    for s in b.exported_symbols:
        print(" ", s.name)
except Exception as e:
    print("err2", e)

print("\n=== STRINGS (JNI/crypto) ===")
raw = open(p, 'rb').read()
for m in re.finditer(rb'[\x20-\x7e]{6,}', raw):
    sk = m.group().decode('ascii', 'replace')
    if ('Java_' in sk or sk.startswith('sm') or 'Decrypt' in sk or 'Encrypt' in sk or 'Cbc' in sk or 'Key' in sk or 'JNI' in sk or 'libkycgm' in sk):
        print("  ", sk[:130])

print("\n=== looking for JNI_OnLoad / RegisterNatives ===")
for n in re.finditer(rb'JNI_OnLoad', raw):
    print("  JNI_OnLoad @", hex(n.start()))
for n in re.finditer(rb'RegisterNatives', raw):
    print("  RegisterNatives str @", hex(n.start()))
