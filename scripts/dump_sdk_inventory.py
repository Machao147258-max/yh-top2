"""Dump SDK inventory: cluster all classes by top-3 package segments.
Identifies all integrated SDKs by package name. No SO reading."""
import zipfile, os, io
from collections import defaultdict, Counter
from contextlib import redirect_stderr, redirect_stdout

buf = io.StringIO()
with redirect_stderr(buf), redirect_stdout(buf):
    from androguard.core.dex import DEX

APK = r"D:\dwonload\yh_gw_20260702.apk"
OUT = r"C:\Users\20751\Desktop\异环\reports\09_SDK_盘点.txt"
z = zipfile.ZipFile(APK)

# Known SDK prefixes to look for
SDK_MARKERS = {
    "com.tencent": "腾讯系 (liteav/thumbplayer/ugc/cloud.huiyansdkface/youtu/bugly/turingface)",
    "com.epicgames": "UE (unreal)",
    "com.laohu": "虎鱼 laohu 账号/支付",
    "com.pwrd": "完美 world (onesdk/onesdkcore)",
    "com.wpsdk": "完美 wpsdk",
    "com.sdk.mxsdk": "完美 mx IM",
    "com.taptap": "TapTap",
    "com.weibo": "微博",
    "com.tencent.tauth": "QQ",
    "com.qq": "QQ/微信",
    "com.umeng": "友盟",
    "com.alipay": "支付宝",
    "cn.com.chinatelecom": "电信统一认证",
    "com.chuanglan": "创蓝闪验",
    "com.cmic": "中国移动认证",
    "com.heytap": "OPPO",
    "com.vivo": "vivo",
    "com.hihonor": "荣耀",
    "com.huawei": "华为",
    "com.deepseek": "深度求索推送",
    "com.DeepSeek": "深度求索",
    "com.baidu": "百度",
    "com.google.android.play.core": "Play Core",
    "com.ace.gshell": "ace gshell",
    "com.hottagames": "异环自研",
    "com.kycgm": "kycgm 国密",
    "com.tencent.bugly": "Bugly",
    "com.tencent.cloud.huiyansdkface": "腾讯云慧眼",
    "com.google.android.gms": "GMS",
    "okhttp3": "OkHttp",
    "kotlinx": "Kotlin 协程",
    "org.json": "JSON",
    "androidx": "AndroidX",
}

by3 = Counter()       # top-3 segments
by_sdk = Counter()    # sdk marker counts
total = 0

for dexname in ["classes.dex","classes2.dex","classes3.dex","classes4.dex","classes5.dex"]:
    with redirect_stderr(buf), redirect_stdout(buf):
        d = DEX(z.read(dexname))
    for cls in d.get_classes():
        total += 1
        cn = cls.get_name()[1:]  # drop L
        parts = cn.split("/")
        key3 = "/".join(parts[:3])
        by3[key3] += 1
        joined = "/".join(parts)
        for marker, label in SDK_MARKERS.items():
            if joined.startswith(marker) or joined.startswith(marker.replace(".","/")):
                by_sdk[label] += 1

lines = []
lines.append("== total classes: %d ==" % total)
lines.append("")
lines.append("== SDK 归属统计（按已知 SDK 前缀）==")
for label, c in by_sdk.most_common():
    lines.append("  %6d  %s" % (c, label))
lines.append("")
lines.append("== top-3 包（未识别 + 已知，前 60）==")
for k, c in by3.most_common(60):
    lines.append("  %6d  %s" % (c, k))

open(OUT,"w",encoding="utf-8").write("\n".join(lines)+"\n")
print("wrote", OUT, "total classes:", total)