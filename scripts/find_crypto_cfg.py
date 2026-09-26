# -*- coding: utf-8 -*-
"""在 异环 目录 + APK 里找 IoStore 加密密钥线索（Crypto.json / EncryptionKey / 32字节候选）。"""
import os, re

ROOTS = [r"C:\Users\20751\Desktop\异环\apk",
         r"C:\Users\20751\Desktop\异环\unpacked"]
KW = [b"Crypto.json", b"EncryptionKey", b"EncryptionKeys", b"PakEncryption",
      b"bEnablePakSigning", b"SigningKey", b"FAES", b"PrimaryKey",
      b"EncryptionKeyGuid", b"IoStoreEncryption", b"AesKey", b"aes_key"]

def scan_file(p):
    try:
        with open(p, "rb") as f:
            d = f.read()
    except Exception:
        return []
    hits = []
    for k in KW:
        i = d.find(k)
        if i >= 0:
            hits.append((k.decode(), i))
    return hits

def main():
    for root in ROOTS:
        if not os.path.exists(root):
            print(f"[skip] {root} 不存在"); continue
        for dp, dn, fn in os.walk(root):
            for name in fn:
                p = os.path.join(dp, name)
                hits = scan_file(p)
                if hits:
                    print(f"\n### {p}")
                    for k, i in hits:
                        print(f"    {k} @ 0x{i:x}")
    # 顺便列出 apk 目录
    print("\n\napk 目录内容:")
    for dp, dn, fn in os.walk(ROOTS[0]):
        for n in fn:
            print("   ", os.path.join(dp, n))

if __name__ == "__main__":
    main()
