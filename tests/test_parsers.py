"""Unit tests for proxy URL parsers / generators in proxyUtil.myUtil."""

from urllib.parse import urlparse

from proxyUtil.myUtil import (
    Create_ss_url,
    Create_ss_url_withPlugin,
    base64Decode,
    extractIPs,
    generate_uuid,
    is_valid_uuid,
    isBase64,
    parse_ss,
    parse_ss_withPlugin,
    parseTrojan,
    parseVless,
)


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
