"""Unit tests for proxy URL parsers / generators."""

from urllib.parse import urlparse

from proxyUtil.parsers import (
    extractIPs,
    parse_ss,
    parse_ss_withPlugin,
    parseTrojan,
    parseVless,
)
from proxyUtil.uri import Create_ss_url, Create_ss_url_withPlugin
from proxyUtil.utils import base64Decode, generate_uuid, is_valid_uuid, isBase64


def test_parse_ss_basic(sample_ss_url):
    server, port, method, password = parse_ss(sample_ss_url)
    assert server == "198.51.100.10"
    assert port == "8388"
    assert method == "aes-256-gcm"
    assert password == "hunter2"


def test_parse_ss_with_plugin(sample_ss_with_plugin_url):
    server, port, method, password, plugin, plugin_opts, tag = parse_ss_withPlugin(
        sample_ss_with_plugin_url
    )
    assert server == "203.0.113.5"
    assert port == "8443"
    assert method == "chacha20-ietf-poly1305"
    assert password == "secret"
    assert plugin == "obfs-local"
    assert plugin_opts == "obfs=tls"
    assert tag == "with-plugin"


def test_create_ss_url_round_trip():
    url = Create_ss_url("203.0.113.5", "8388", "aes-256-gcm", "pa$$word")
    server, port, method, password = parse_ss(url)
    assert (server, port, method, password) == ("203.0.113.5", "8388", "aes-256-gcm", "pa$$word")


def test_create_ss_url_with_plugin_round_trip():
    url = Create_ss_url_withPlugin(
        "203.0.113.5",
        "8443",
        "chacha20-ietf-poly1305",
        "secret",
        plugin="v2ray-plugin",
        plugin_opts="server",
        tag="rt-test",
    )
    server, port, method, password, plugin, plugin_opts, tag = parse_ss_withPlugin(url)
    assert server == "203.0.113.5"
    assert port == "8443"
    assert method == "chacha20-ietf-poly1305"
    assert password == "secret"
    assert plugin == "v2ray-plugin"
    assert plugin_opts == "server"
    assert tag == "rt-test"


def test_parse_vless(sample_vless_url):
    parsed = parseVless(urlparse(sample_vless_url))
    assert parsed["add"] == "198.51.100.20"
    assert parsed["port"] == "443"
    assert parsed["id"] == "11111111-1111-1111-1111-111111111111"
    assert parsed["net"] == "ws"
    assert parsed["tls"] == "tls"
    assert parsed["protocol"] == "vless"


def test_parse_trojan(sample_trojan_url):
    parsed = parseTrojan(urlparse(sample_trojan_url))
    assert parsed["address"] == "198.51.100.30"
    assert parsed["port"] == "443"
    assert parsed["password"] == "hunter2"
    assert parsed["security"] == "tls"


def test_is_valid_uuid_pair():
    assert is_valid_uuid("11111111-1111-1111-1111-111111111111") is True
    assert is_valid_uuid("not-a-uuid") is False


def test_generate_uuid_deterministic():
    assert generate_uuid("seed-x") == generate_uuid("seed-x")
    assert generate_uuid("seed-x") != generate_uuid("seed-y")
    assert is_valid_uuid(generate_uuid("seed-x"))


def test_isBase64_true_false():
    assert isBase64("YWJjZA==") is True  # "abcd"
    assert isBase64("not_base64!@#$") is False


def test_base64Decode_handles_missing_padding():
    # Standard base64 of "ok" is "b2s=" — strip the padding to test the helper.
    assert base64Decode("b2s") == "ok"
    # URL-safe alphabet path
    assert base64Decode("b2s_") == "okÿ" or base64Decode("b2s_").startswith("ok")


def test_extractIPs_ss(sample_ss_url):
    assert extractIPs(sample_ss_url) == "198.51.100.10"


def test_extractIPs_vless(sample_vless_url):
    assert extractIPs(sample_vless_url) == "198.51.100.20"


def test_parse_trojan_aliases_peer_to_sni():
    parsed = parseTrojan(urlparse("trojan://pw@example.com:443?peer=example.org&type=tcp"))
    assert parsed["sni"] == "example.org"


def test_parse_trojan_normalizes_allowinsecure():
    parsed = parseTrojan(urlparse("trojan://pw@example.com:443?allowinsecure=true&sni=example.com"))
    assert parsed["allowInsecure"] == "1"

    parsed_off = parseTrojan(urlparse("trojan://pw@example.com:443?allowInsecure=0"))
    assert parsed_off["allowInsecure"] == "0"


def test_create_vmess_config_xhttp_transport():
    from proxyUtil.xray import createVmessConfig

    payload = {
        "add": "example.com",
        "port": "443",
        "id": "11111111-1111-1111-1111-111111111111",
        "net": "xhttp",
        "tls": "tls",
        "host": "cdn.example.com",
        "path": "/x",
        "mode": "stream-up",
        "sni": "cdn.example.com",
        "fp": "chrome",
        "alpn": "h2,http/1.1",
    }
    cfg = createVmessConfig(payload, port=1080)
    stream = cfg["outbounds"][0]["streamSettings"]
    assert stream["network"] == "xhttp"
    assert stream["xhttpSettings"]["mode"] == "stream-up"
    assert stream["xhttpSettings"]["host"] == "cdn.example.com"
    assert stream["tlsSettings"]["fingerprint"] == "chrome"
    assert stream["tlsSettings"]["alpn"] == ["h2", "http/1.1"]


def test_create_vmess_config_httpupgrade_transport():
    from proxyUtil.xray import createVmessConfig

    payload = {
        "add": "example.com",
        "port": "443",
        "id": "11111111-1111-1111-1111-111111111111",
        "net": "httpupgrade",
        "tls": "tls",
        "host": "cdn.example.com",
        "path": "/hu",
        "sni": "cdn.example.com",
    }
    cfg = createVmessConfig(payload, port=1080)
    stream = cfg["outbounds"][0]["streamSettings"]
    assert stream["network"] == "httpupgrade"
    assert stream["httpupgradeSettings"]["path"] == "/hu"


def test_create_vmess_config_vision_flow_filter():
    from proxyUtil.xray import createVmessConfig

    payload = {
        "add": "example.com",
        "port": "443",
        "id": "11111111-1111-1111-1111-111111111111",
        "net": "tcp",
        "tls": "reality",
        "flow": "xtls-rprx-vision",
        "pbk": "publickey",
        "sid": "sid",
        "sni": "example.com",
    }
    cfg = createVmessConfig(payload)
    user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert user.get("flow") == "xtls-rprx-vision"

    payload["flow"] = "xtls-rprx-direct"
    cfg = createVmessConfig(payload)
    user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert "flow" not in user


def test_singbox_hysteria2_outbound():
    from proxyUtil.singbox import build_singbox_config

    url = (
        "hy2://Yet-Another-Public-Config-1@206.71.158.37:35200"
        "?obfs=salamander&obfs-password=secret&insecure=1&sni=YAPC.example.com"
    )
    cfg = build_singbox_config(url, 1080)
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "hysteria2"
    assert out["server"] == "206.71.158.37"
    assert out["server_port"] == 35200
    assert out["password"] == "Yet-Another-Public-Config-1"
    assert out["obfs"] == {"type": "salamander", "password": "secret"}
    assert out["tls"]["insecure"] is True
    assert out["tls"]["server_name"] == "YAPC.example.com"


def test_singbox_tuic_outbound():
    from proxyUtil.singbox import build_singbox_config

    url = (
        "tuic://aaaa-bbbb-cccc:supersecret@host.example.com:443"
        "?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=host.example.com"
    )
    cfg = build_singbox_config(url, 1080)
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "tuic"
    assert out["uuid"] == "aaaa-bbbb-cccc"
    assert out["password"] == "supersecret"
    assert out["congestion_control"] == "bbr"
    assert out["tls"]["alpn"] == ["h3"]


def test_singbox_hysteria_v1_outbound():
    from proxyUtil.singbox import build_singbox_config

    url = (
        "hysteria://1.2.3.4:5678?upmbps=11&downmbps=55"
        "&auth=mypw&insecure=1&peer=cdn.example.com&alpn=h3"
    )
    cfg = build_singbox_config(url, 1080)
    assert cfg is not None
    out = cfg["outbounds"][0]
    assert out["type"] == "hysteria"
    assert out["auth_str"] == "mypw"
    assert out["up_mbps"] == 11
    assert out["down_mbps"] == 55
    assert out["tls"]["server_name"] == "cdn.example.com"


def test_extractIPs_hysteria2():
    from proxyUtil.parsers import extractIPs

    assert extractIPs("hysteria2://pw@198.51.100.40:443?sni=x") == "198.51.100.40"


def test_parse_ssr_without_query_args():
    """parse_ssr must not crash when the URL omits the trailing /? args section."""
    import base64

    body = (
        "203.0.113.5:8388:auth_aes128_md5:aes-256-cfb:plain:"
        + base64.urlsafe_b64encode(b"pw").rstrip(b"=").decode()
    )
    url = "ssr://" + base64.urlsafe_b64encode(body.encode()).rstrip(b"=").decode()
    from proxyUtil.parsers import parse_ssr

    parsed = parse_ssr(url)
    assert parsed["address"] == "203.0.113.5"
    assert parsed["password"] == "pw"
    assert parsed["obfsparam"] == ""
