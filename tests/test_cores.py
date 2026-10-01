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


def _ss(method):
    import base64

    raw = base64.urlsafe_b64encode(f"{method}:pw".encode()).decode().rstrip("=")
    return f"ss://{raw}@203.0.113.1:8388"


def test_xray_family_rejects_legacy_ciphers_but_singbox_accepts():
    for name in ("xray", "v2ray"):
        reason = cores.get(name).unsupported_reason(_ss("aes-256-cfb"))
        assert reason and "aes-256-cfb" in reason and "sing-box" in reason
        assert cores.get(name).unsupported_reason(_ss("aes-256-gcm")) is None
    assert cores.get("sing-box").unsupported_reason(_ss("aes-256-cfb")) is None


def test_cipher_support_differs_between_xray_and_v2ray():
    # measured against the real binaries: v2ray 5.x has no xchacha20 / ss-2022
    assert cores.get("xray").unsupported_reason(_ss("xchacha20-ietf-poly1305")) is None
    assert cores.get("v2ray").unsupported_reason(_ss("xchacha20-ietf-poly1305")) is not None
    assert cores.get("xray").unsupported_reason(_ss("2022-blake3-aes-256-gcm")) is None
    assert cores.get("v2ray").unsupported_reason(_ss("2022-blake3-aes-256-gcm")) is not None


def test_non_ss_urls_pass_cipher_check():
    assert cores.get("xray").unsupported_reason("vless://id@h:443") is None
    assert cores.get("xray").unsupported_reason("ss://garbage") is None


def test_pick_auto_prefers_singbox_then_xray_then_v2ray(monkeypatch):
    present = {"sing-box", "xray", "v2ray"}
    monkeypatch.setattr(cores.shutil, "which", lambda b: b if b in present else None)
    assert cores.pick_auto().name == "sing-box"
    present.discard("sing-box")
    assert cores.pick_auto().name == "xray"
    present.discard("xray")
    assert cores.pick_auto().name == "v2ray"
    present.clear()
    assert cores.pick_auto() is None


def test_every_core_has_batch_builder_and_check_argv():
    for spec in cores.REGISTRY.values():
        assert spec.build_batch and spec.check_argv


def test_batch_config_shape_unique_tags_and_routing():
    from proxyUtil import singbox, xray

    urls = [
        ("ss://YWVzLTEyOC1nY206cGFzc3dk@203.0.113.1:8388", 41001),
        ("hysteria2://pw@x:1", 41002),  # xray can't build it: skipped, not fatal
        ("trojan://pw@203.0.113.2:443?security=tls", 41003),
    ]
    cfg, built = xray.createBatchConfig(urls)
    assert built == [0, 2]
    assert [i["port"] for i in cfg["inbounds"]] == [41001, 41003]
    assert all(i["listen"] == "127.0.0.1" for i in cfg["inbounds"])
    assert [r["outboundTag"] for r in cfg["routing"]["rules"]] == ["out0", "out1"]
    assert {o["tag"] for o in cfg["outbounds"]} == {"out0", "out1"}

    cfg, built = singbox.build_singbox_batch(urls)
    assert built == [0, 1, 2]
    assert [i["listen_port"] for i in cfg["inbounds"]] == [41001, 41002, 41003]
    assert len({o["tag"] for o in cfg["outbounds"]}) == 3
    assert cfg["route"]["rules"][1] == {"inbound": ["in1"], "action": "route", "outbound": "out1"}


def test_xray_templates_do_not_force_allow_insecure():
    # xray >= 2026-06-01 rejects any config containing allowInsecure, so a template that
    # forces it makes every TLS config fail. Only an explicit request may emit it.
    from proxyUtil import xray

    for url in (
        "trojan://pw@203.0.113.2:443?security=tls&sni=a.example",
        "vless://11111111-1111-1111-1111-111111111111@203.0.113.3:443?security=tls&type=ws",
    ):
        stream = xray.createConfig(url, 1080)["outbounds"][0]["streamSettings"]
        assert "allowInsecure" not in stream.get("tlsSettings", {})
    asked = xray.createConfig("trojan://pw@203.0.113.2:443?security=tls&allowInsecure=1", 1080)[
        "outbounds"
    ][0]["streamSettings"]
    assert asked["tlsSettings"]["allowInsecure"] is True


def test_xray_flags_cert_skipping_configs_after_removal_date(monkeypatch):
    import datetime

    insecure = "trojan://pw@h:443?security=tls&allowInsecure=1"
    strict = "trojan://pw@h:443?security=tls"
    spec = cores.get("xray")
    assert "allowInsecure" in spec.unsupported_reason(insecure)  # today is past 2026-06-01
    assert spec.unsupported_reason(strict) is None
    assert cores.get("sing-box").unsupported_reason(insecure) is None
    assert cores.get("v2ray").unsupported_reason(insecure) is None

    class Before(datetime.date):
        @classmethod
        def today(cls):
            return cls(2026, 5, 31)

    monkeypatch.setattr(cores.datetime, "date", Before)
    assert spec.unsupported_reason(insecure) is None
