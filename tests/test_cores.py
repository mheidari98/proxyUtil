"""Tests for the core registry and the sing-box scheme expansion (anytls,
shadowtls, naive, ssh, wireguard, juicity, Reality 3-flag invariant)."""

from __future__ import annotations

from proxyUtil import cores
from proxyUtil.singbox import build_singbox_config


def test_registry_lists_three_cores():
    assert cores.CORE_NAMES == ("xray", "v2ray", "sing-box")


def test_xray_scheme_set_classic_only():
    spec = cores.get("xray")
    assert "vless" in spec.schemes
    assert "trojan" in spec.schemes
    assert "ss" in spec.schemes
    assert "ssr" in spec.schemes
    assert "hysteria2" not in spec.schemes
    assert "tuic" not in spec.schemes


def test_singbox_scheme_set_includes_modern():
    spec = cores.get("sing-box")
    for scheme in (
        "vless",
        "trojan",
        "ss",
        "hysteria2",
        "tuic",
        "anytls",
        "shadowtls",
        "naive",
        "ssh",
        "wireguard",
        "juicity",
    ):
        assert scheme in spec.schemes


def test_registry_run_argv_uses_dash_c():
    spec = cores.get("xray")
    assert spec.run_argv("xray", "/tmp/cfg") == ["xray", "run", "-c", "/tmp/cfg"]
    sb = cores.get("sing-box")
    assert sb.run_argv("sing-box", "/tmp/cfg") == ["sing-box", "run", "-c", "/tmp/cfg"]


def test_singbox_anytls_outbound():
    cfg = build_singbox_config(
        "anytls://mypassword@host.example.com:443?sni=host.example.com", 1080
    )
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "anytls"
    assert out["password"] == "mypassword"
    assert out["tls"]["server_name"] == "host.example.com"


def test_singbox_shadowtls_v3_outbound():
    cfg = build_singbox_config(
        "shadowtls://secret@host.example.com:443?sni=cdn.example.com&version=3", 1080
    )
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "shadowtls"
    assert out["version"] == 3
    assert out["password"] == "secret"


def test_singbox_naive_outbound():
    cfg = build_singbox_config(
        "naive+https://user:pass@host.example.com:443?sni=cdn.example.com", 1080
    )
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "naive"
    assert out["username"] == "user"
    assert out["password"] == "pass"


def test_singbox_ssh_outbound():
    cfg = build_singbox_config("ssh://root:hunter2@198.51.100.10:22", 1080)
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "ssh"
    assert out["user"] == "root"
    assert out["password"] == "hunter2"


def test_singbox_wireguard_outbound():
    cfg = build_singbox_config(
        "wireguard://privkeyb64@198.51.100.50:51820?publickey=PUB&address_v4=10.0.0.2/32", 1080
    )
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "wireguard"
    assert out["private_key"] == "privkeyb64"
    assert out["peer_public_key"] == "PUB"


def test_singbox_juicity_emitted_as_tuic_bbr():
    cfg = build_singbox_config("juicity://uuid:pwd@host.example.com:443?sni=host.example.com", 1080)
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "tuic"
    assert out["congestion_control"] == "bbr"
    assert out["udp_relay_mode"] == "native"


def test_singbox_vless_reality_three_flag_invariant():
    url = (
        "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443"
        "?type=tcp&security=reality&flow=xtls-rprx-vision"
        "&sni=cdn.example.com&pbk=PUBKEY&sid=SHORT&fp=chrome"
    )
    cfg = build_singbox_config(url, 1080)
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["flow"] == "xtls-rprx-vision"
    tls = out["tls"]
    assert tls["enabled"] is True
    assert tls["utls"]["enabled"] is True
    assert tls["utls"]["fingerprint"] == "chrome"
    assert tls["reality"]["enabled"] is True
    assert tls["reality"]["public_key"] == "PUBKEY"
    assert tls["reality"]["short_id"] == "SHORT"


def test_singbox_xhttp_downgrades_to_httpupgrade(caplog):
    url = (
        "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443"
        "?type=xhttp&security=tls&path=/x&host=cdn.example.com&sni=cdn.example.com"
    )
    with caplog.at_level("DEBUG"):
        cfg = build_singbox_config(url, 1080)
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["transport"]["type"] == "httpupgrade"
    assert out["transport"]["host"] == "cdn.example.com"
    assert any("downgrading to httpupgrade" in r.message for r in caplog.records)


def test_singbox_unknown_scheme_returns_none():
    assert build_singbox_config("imaginary://foo@bar:1234", 1080) is None


def test_xray_unknown_scheme_returns_none():
    from proxyUtil.xray import createConfig

    assert createConfig("hysteria2://pw@host:443", 1080) is None
