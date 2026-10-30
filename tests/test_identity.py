"""proxy_identity normalization + invalid_reason structural validation (offline)."""

import base64
import json
from collections import Counter

import pytest

from proxyUtil.parsers import dedupe_proxies, invalid_reason, proxy_identity, reject_invalid

UUID = "0c3a5e5e-7f3b-4c1e-9d2a-1b2c3d4e5f60"


def vmess(payload, *, urlsafe=False, pad=True):
    raw = json.dumps(payload).encode()
    enc = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode()
    return "vmess://" + (enc if pad else enc.rstrip("="))


VMESS = {
    "v": "2",
    "ps": "name",
    "add": "Proxy.Foo.com",
    "port": "443",
    "id": UUID,
    "aid": "0",
    "net": "ws",
    "type": "none",
    "host": "cdn.foo.com",
    "path": "/ws",
    "tls": "tls",
    "sni": "cdn.foo.com",
}


def same(*urls):
    keys = {proxy_identity(u) for u in urls}
    assert len(keys) == 1, keys


def differ(a, b):
    assert proxy_identity(a) != proxy_identity(b)


def test_identity_is_version_tagged():
    assert proxy_identity(f"vless://{UUID}@1.2.3.4:443").startswith("id1:")
    assert proxy_identity("vmess://%%%not-base64") == "raw:vmess://%%%not-base64"
    assert proxy_identity("garbage#tag") == "raw:garbage"


def test_names_and_scheme_host_case_ignored():
    same(
        f"vless://{UUID}@Proxy.Foo.com:443?type=ws&path=%2Fws#a",
        f"VLESS://{UUID.upper()}@proxy.foo.com:0443?path=/ws&type=ws#b",
    )
    differ(f"vless://{UUID}@h.foo.com:443", f"vless://{UUID}@h.foo.com:444")


def test_query_order_aliases_and_client_knobs():
    base = f"vless://{UUID}@1.2.3.4:443?security=tls&sni=a.foo.com&type=ws&host=a.foo.com&path=/x"
    same(
        base,
        f"vless://{UUID}@1.2.3.4:443/?path=%2Fx&host=a.foo.com&type=ws&peer=a.foo.com&security=tls"
        "&fp=chrome&alpn=h2,http/1.1&allowInsecure=1&encryption=none&headerType=none",
        f"vless://{UUID}@1.2.3.4:443?security=tls&amp;sni=a.foo.com&amp;type=ws&amp;host=a.foo.com"
        "&amp;path=/x&amp;insecure=0",
    )
    differ(base, base.replace("path=/x", "path=/y"))
    differ(base, base.replace("sni=a.foo.com", "sni=b.foo.com"))
    # an explicit sni wins over peer, whatever the order
    same(
        "trojan://pw@1.2.3.4:443?peer=x.foo.com&sni=y.foo.com",
        "trojan://pw@1.2.3.4:443?sni=y.foo.com",
    )


def test_defaults_spelled_out_or_omitted():
    same(
        f"vless://{UUID}@1.2.3.4:443",
        f"vless://{UUID}@1.2.3.4:443/?type=tcp&security=none&encryption=none&headerType=none",
        f"vless://{UUID}@1.2.3.4:443?type=raw&flow=&sid=",
    )
    # plain TCP sends no HTTP request: channel spam in host/path does not split identity
    same(
        f"vless://{UUID}@1.2.3.4:443?security=reality&pbk=K&sni=a.com",
        f"vless://{UUID}@1.2.3.4:443?security=reality&pbk=K&sni=a.com&host=%3Ftelegram&path=/",
    )
    differ(f"vless://{UUID}@1.2.3.4:443?type=ws&host=a.com", f"vless://{UUID}@1.2.3.4:443?type=ws")
    differ(
        f"vless://{UUID}@1.2.3.4:443?security=reality&pbk=K",
        f"vless://{UUID}@1.2.3.4:443?security=reality&pbk=k",
    )


def test_case_sensitive_values_are_kept():
    differ(
        f"vless://{UUID}@1.2.3.4:443?encryption=mlkem768x25519plus.native.0rtt.AbC",
        f"vless://{UUID}@1.2.3.4:443?encryption=mlkem768x25519plus.native.0rtt.abc",
    )
    differ("trojan://PassWord@1.2.3.4:443", "trojan://password@1.2.3.4:443")


def test_trojan_tls_is_the_default():
    same("trojan://pw@1.2.3.4:443", "trojan://pw@1.2.3.4:443?security=tls&type=tcp")
    differ("trojan://pw@1.2.3.4:443", "trojan://pw@1.2.3.4:443?security=none")


def test_hysteria2_aliases_ports_and_hopping():
    same(
        "hy2://pw@1.2.3.4?sni=a.foo.com&insecure=1",
        "hysteria2://pw@1.2.3.4:443/?sni=a.foo.com&security=tls&allow_insecure=1",
    )
    same(
        "hysteria2://pw@1.2.3.4:443,20000-30000?sni=a.foo.com",
        "hysteria2://pw@1.2.3.4:443?mport=20000-30000&sni=a.foo.com",
        "hy2://pw@1.2.3.4:443?mport=20000:30000,443&sni=a.foo.com",
    )
    differ("hysteria2://pw@1.2.3.4:443", "hysteria2://pw@1.2.3.4:443?mport=20000-30000")
    same("hysteria://1.2.3.4:443?auth_str=x&up=10", "hysteria://1.2.3.4:443?auth=x&upmbps=10")


def test_tuic_congestion_alias_and_uuid_case():
    same(
        f"tuic://{UUID}:pw@1.2.3.4:443?congestion_control=bbr&alpn=h3",
        f"tuic://{UUID.upper()}:pw@1.2.3.4:443?congestion-control=BBR",
    )
    differ(f"tuic://{UUID}:pw@1.2.3.4:443", f"tuic://{UUID}:PW@1.2.3.4:443")


def test_ipv6_brackets_and_spelling():
    same(
        f"vless://{UUID}@[2001:DB8:0::1]:443#a",
        f"vless://{UUID}@[2001:db8::1]:443",
    )
    v6 = dict(VMESS, add="2001:db8::1")
    same(vmess(v6), vmess(dict(v6, add="[2001:DB8::1]")))


def test_vmess_normalization():
    same(
        vmess(VMESS),
        vmess(VMESS, urlsafe=True, pad=False),
        vmess(dict(VMESS, ps="other", v=2, port=443, aid=0, id=UUID.upper(), fp="chrome")),
        vmess(dict(VMESS, scy="auto", alpn="", test_name="104", **{"skip-cert-verify": True})),
        vmess({k: v for k, v in VMESS.items() if k not in ("v", "aid", "type")}),
        vmess(VMESS) + "#tag",
    )
    plain = dict(VMESS, net="tcp", tls="", host="", path="", sni="")
    same(
        vmess(plain),
        vmess(dict(plain, tls=None, net="raw", type="---")),
        vmess({k: v for k, v in plain.items() if k not in ("tls", "net", "host", "path", "sni")}),
        vmess(dict(plain, tls=False, net="tcp#junk")),
    )
    differ(vmess(VMESS), vmess(dict(VMESS, path="/other")))
    differ(vmess(VMESS), vmess(dict(VMESS, aid="64")))
    differ(vmess(VMESS), vmess(dict(VMESS, scy="none")))
    differ(vmess(plain), vmess(dict(plain, type="http")))
    # vmess and vless with the same fields stay distinct
    differ(vmess(VMESS), f"vless://{UUID}@proxy.foo.com:443?type=ws")


def test_ss_forms_and_plugin():
    userinfo = "aes-256-gcm:pa@ss"
    b64 = base64.urlsafe_b64encode(userinfo.encode()).decode()
    legacy = base64.b64encode(f"{userinfo}@1.2.3.4:8388".encode()).decode()
    same(
        f"ss://{b64}@1.2.3.4:8388#a",
        f"ss://{b64.rstrip('=')}@1.2.3.4:8388/#b",
        f"ss://{legacy}#c",
        "ss://AES-256-GCM:pa%40ss@1.2.3.4:8388",
    )
    with_plugin = f"ss://{b64}@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Da.com"
    same(with_plugin, f"ss://{b64}@1.2.3.4:8388?plugin=simple-obfs;obfs-host=a.com;obfs=tls")
    differ(with_plugin, f"ss://{b64}@1.2.3.4:8388")
    differ(f"ss://{b64}@1.2.3.4:8388", "ss://aes-256-gcm:Pa@ss@1.2.3.4:8388")


def test_ssr_drops_remarks():
    def ssr(remarks):
        tag = base64.urlsafe_b64encode(remarks.encode()).decode()
        pw = base64.urlsafe_b64encode(b"secret").decode()
        body = f"1.2.3.4:8388:origin:aes-256-cfb:plain:{pw}/?remarks={tag}"
        return "ssr://" + base64.urlsafe_b64encode(body.encode()).decode()

    same(ssr("one"), ssr("two"))
    assert proxy_identity(ssr("one")).startswith("id1:ssr://secret@1.2.3.4:8388?")


def test_dedupe_keeps_first_of_each_identity():
    a = f"vless://{UUID}@1.2.3.4:443?fp=chrome#first"
    b = f"vless://{UUID}@1.2.3.4:443?fp=firefox&type=tcp#second"
    c = f"vless://{UUID}@1.2.3.4:444#third"
    assert dedupe_proxies([a, b, c, a]) == [a, c]


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        (f"vless://{UUID}@1.2.3.4:443?security=tls", None),
        (vmess(VMESS), None),
        ("hy2://pw@a.foo.com?sni=x.com", None),
        ("hysteria2://pw@1.2.3.4:20000-30000", None),
        ("ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388", None),
        ("ss://rc4-md5:pw@1.2.3.4:8388", None),  # ciphers are the cores' call
        ("not a proxy", "unparsable"),
        ("vless://35g53vf34854hs#x", "port"),
        ("vmess://%%%", "base64"),
        ("vmess://" + base64.b64encode(b"[1, 2]").decode(), "unparsable"),
        (f"vless://{UUID}@1.2.3.4:0", "port"),
        (f"vless://{UUID}@1.2.3.4:1", "port"),
        (f"vless://{UUID}@1.2.3.4:65536", "port"),
        (f"vless://{UUID}@1.2.3.4:abc", "port"),
        (f"vless://{UUID}@1.2.3.4", "port"),
        (f"vless://{UUID}@:443", "host"),
        (f"vless://{UUID}@localhost:443", "host"),
        (f"vless://{UUID}@0.0.0.0:443", "host"),
        (f"vless://{UUID}@[::]:443", "host"),
        (f"vless://{UUID}@printer.local:443", "host"),
        (f"vless://{UUID}@a.example.com:443", "host"),
        (f"vless://{UUID}@x.invalid:443", "host"),
        (f"vless://{UUID}@7nXKCe_VLESS:443", "host"),
        (f"vless://{UUID}@127.0.0.1:443", "private-ip"),
        (f"vless://{UUID}@10.1.2.3:443", "private-ip"),
        (f"vless://{UUID}@192.168.1.1:443", "private-ip"),
        (f"vless://{UUID}@169.254.1.1:443", "private-ip"),
        (f"vless://{UUID}@100.64.0.1:443", "private-ip"),
        (f"vless://{UUID}@224.0.0.1:443", "private-ip"),
        (f"vless://{UUID}@240.0.0.1:443", "private-ip"),
        (f"vless://{UUID}@[fe80::1]:443", "private-ip"),
        (f"vless://{UUID}@[::ffff:10.0.0.1]:443", "private-ip"),
        ("vless://@1.2.3.4:443", "no-credential"),
        ("vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443", "no-credential"),
        (vmess(dict(VMESS, id="")), "no-credential"),
        ("tuic://:pw@1.2.3.4:443", "no-credential"),
        ("trojan://@1.2.3.4:443", "no-credential"),
        ("hysteria2://1.2.3.4:443", "no-credential"),
        ("ss://YWVzLTI1Ni1nY206@1.2.3.4:8388", "no-credential"),
    ],
)
def test_invalid_reason(url, reason):
    assert invalid_reason(url) == reason


def test_reject_invalid_counts_reasons():
    good = [f"vless://{UUID}@1.2.3.4:443", "trojan://pw@a.foo.com:443"]
    bad = [f"vless://{UUID}@127.0.0.1:443", f"vless://{UUID}@10.0.0.1:443", "junk"]
    kept, reasons = reject_invalid([bad[0], good[0], bad[1], good[1], bad[2]])
    assert kept == good
    assert reasons == Counter({"private-ip": 2, "unparsable": 1})
