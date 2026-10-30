"""_common helpers and transport sanitising (offline)."""

import argparse
import base64
import json
import logging
import socket

import pytest

import proxyUtil.net as net
from proxyUtil._common import add_source_args, collect_proxies, find_free_ports
from proxyUtil.net import FetchResult
from proxyUtil.utils import normalize_network


def test_find_free_ports_skips_bound_port_even_when_not_connectable():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))  # bound but not listening: connect_ex-based probing missed this
    busy = s.getsockname()[1]
    try:
        assert busy not in find_free_ports(busy, 3)
    finally:
        s.close()


def test_find_free_ports_gives_up_past_65535():
    with pytest.raises(RuntimeError):
        find_free_ports(65536, 1)


def _args(argv):
    p = argparse.ArgumentParser()
    add_source_args(p)
    return p.parse_args(argv)


def test_url_is_repeatable_and_sources_file_is_read(tmp_path, monkeypatch, caplog):
    src = tmp_path / "srcs.txt"
    src.write_text("# comment\nhttp://c.example/sub\n\nhttp://a.example/sub\n")
    bodies = {
        "http://a.example/sub": ("ss://aaa@h:1", "ss://bbb@h:1"),
        "http://b.example/sub": ("ss://bbb@h:1",),
        "http://c.example/sub": (),
    }

    def fake_fetch(url, patterns=None, **_):
        if url == "http://c.example/sub":
            return FetchResult(url, error="HTTP 503")
        return FetchResult(url, proxies=bodies[url], http_status=200)

    monkeypatch.setattr(net, "fetchSource", fake_fetch)
    args = _args(
        ["--url", "http://a.example/sub", "--url", "http://b.example/sub", "--sources", str(src)]
    )
    with caplog.at_level(logging.INFO):
        lines = collect_proxies(args, free_url="http://free.example")
    assert lines == ["ss://aaa@h:1", "ss://bbb@h:1"]  # deduped, first-seen order
    assert "http://c.example/sub: FAILED (HTTP 503)" in caplog.text  # dead source is visible


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ws", "ws"),
        ("", "tcp"),
        (None, "tcp"),
        ("ws🌐", "ws"),
        ("tcp@freev2configs", "tcp"),
        ("WS", "ws"),
        ("🌐", "tcp"),
    ],
)
def test_normalize_network(raw, expected):
    assert normalize_network(raw) == expected


def _vmess(**over):
    payload = {
        "v": "2",
        "ps": "t",
        "add": "198.51.100.1",
        "port": "443",
        "id": "22222222-2222-2222-2222-222222222222",
        "aid": "0",
        **over,
    }
    return "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()


def test_vmess_missing_net_and_tls_no_longer_crashes_xray(caplog):
    from proxyUtil import xray

    url = _vmess()  # no "net", no "tls": used to KeyError and get skipped
    with caplog.at_level(logging.WARNING):
        cfg = xray.createConfig(url, 1080)
    assert cfg is not None and cfg["outbounds"][0]["streamSettings"]["network"] == "tcp"
    assert "unsupported transport" not in caplog.text


def test_vmess_junk_transport_is_cleaned_for_both_cores():
    from proxyUtil import singbox, xray

    url = _vmess(net="ws🌐", path="/p", host="h.example", tls="")
    assert xray.createConfig(url, 1080)["outbounds"][0]["streamSettings"]["network"] == "ws"
    out = singbox.build_singbox_config(url, 1080)["outbounds"][0]
    assert out["transport"]["type"] == "ws"
