from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def sample_ss_url() -> str:
    # method:password@server:port  →  ss://base64(...)#tag
    import base64

    raw = "aes-256-gcm:hunter2@198.51.100.10:8388"
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    return f"ss://{encoded}#test-ss"


@pytest.fixture
def sample_ss_with_plugin_url() -> str:
    import base64
    from urllib.parse import quote_plus

    userinfo = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:secret").decode().rstrip("=")
    plugin_q = quote_plus("obfs-local;obfs=tls")
    return f"ss://{userinfo}@203.0.113.5:8443/?plugin={plugin_q}#with-plugin"


@pytest.fixture
def sample_vless_url() -> str:
    return "vless://11111111-1111-1111-1111-111111111111@198.51.100.20:443?type=ws&path=/&host=cdn.example.com&security=tls&sni=cdn.example.com#vless-test"


@pytest.fixture
def sample_trojan_url() -> str:
    return "trojan://hunter2@198.51.100.30:443?security=tls&sni=tj.example.com&type=tcp#trojan-test"


@pytest.fixture
def sample_vmess_url() -> str:
    # vmess uses base64-encoded JSON
    import base64
    import json

    payload = {
        "v": "2",
        "ps": "vmess-test",
        "add": "198.51.100.40",
        "port": "443",
        "id": "22222222-2222-2222-2222-222222222222",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "vm.example.com",
        "path": "/",
        "tls": "tls",
        "sni": "vm.example.com",
    }
    return "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
