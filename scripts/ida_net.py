# -*- coding: utf-8 -*-
"""idalib 深度：网络层符号 xref（socket/SSL/HTTP/UE 网络栈）。"""
import io, traceback
I64 = r"C:\Users\20751\Desktop\异环\unpacked\so\libUnreal.so.i64"
OUT = r"C:\Users\20751\Desktop\异环\reports\32_libUnreal_net.md"

# 关注的子串
PATS = ["ISocketSubsystem","FSocketBSD","SocketBSD","getaddrinfo","sendto","recvfrom",
        "GetHostByName","FInternetAddr","Socket::","SSL_connect","SSL_write","SSL_read",
        "TLSClient","FTcpSocketBuilder","FHttpModule","IHttpRequest","HttpRequest",
        "SslCertificate","X509_","SSL_CTX","FNetworkPlatformFile","SocketSubsystem",
        "FOnlineSubsystem","WebSocket","UdpSocket","TCPConnection","FNetDriver",
        "PacketHandler","NetConnection","OodleNetworkHandler"]

buf=io.StringIO()
def log(*a):
    s=" ".join(str(x) for x in a); print(s); buf.write(s+"\n")
try:
    import idapro
    idapro.open_database(I64, False)
    import idautils, ida_funcs, ida_name, ida_hexrays

    hits={p:[] for p in PATS}
    for s in idautils.Strings():
        try: v=str(s)
        except: continue
        for p in PATS:
            if p in v:
                refs=[]
                for r in idautils.XrefsTo(s.ea):
                    f=ida_funcs.get_func(r.frm)
                    refs.append((r.frm, f.start_ea if f else 0))
                hits[p].append((s.ea, v[:90], refs[:5]))
    for p in PATS:
        if hits[p]:
            log(f"\n### {p}  ({len(hits[p])})")
            for ea,v,refs in hits[p][:10]:
                log(f"  str@0x{ea:x} {v!r}")
                for frm,fs in refs: log(f"      <- 0x{frm:x} func@0x{fs:x}")
    idapro.close_database()
except Exception:
    log("异常:\n"+traceback.format_exc())
open(OUT,"w",encoding="utf-8").write(buf.getvalue())
print("写出:",OUT)
