import base64
import json
import socket
import threading

import pytest

from proxyUtil import prefilter as pf
from proxyUtil.parsers import dedupe_proxies, proxy_identity


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(50)
    yield s.getsockname()[1]
    s.close()


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def vmess(host, port, **extra):
    body = {"v": "2", "ps": "n", "add": host, "port": str(port), "id": "x", **extra}
    return "vmess://" + base64.b64encode(json.dumps(body).encode()).decode()


def test_endpoints_for_each_scheme():
    ss = (
        "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=") + "@1.2.3.4:8388"
    )
    assert pf.server_endpoint(ss) == ("1.2.3.4", 8388)
    assert pf.server_endpoint(vmess("h.example", 443)) == ("h.example", 443)
    assert pf.server_endpoint("vless://id@h.example:2053?type=ws#n") == ("h.example", 2053)
    assert pf.server_endpoint("trojan://pw@9.9.9.9:443") == ("9.9.9.9", 443)
    assert pf.server_endpoint("vless://broken") is None


def test_udp_schemes_and_transports_are_never_judged_by_tcp():
    assert not pf.needs_tcp_check("hysteria2://pw@h:443")
    assert not pf.needs_tcp_check("tuic://u:p@h:443")
    assert not pf.needs_tcp_check("vless://id@h:443?type=kcp")
    assert not pf.needs_tcp_check(vmess("h", 1, net="quic"))
    assert pf.needs_tcp_check("vless://id@h:443?type=ws")
    assert pf.needs_tcp_check(vmess("h", 1, net="ws🌐"))


def test_prefilter_keeps_open_drops_closed_keeps_unjudgeable(listener):
    open_url = f"vless://id@127.0.0.1:{listener}?type=ws#open"
    dead_url = f"vless://id@127.0.0.1:{closed_port()}?type=ws#dead"
    udp_url = f"hysteria2://pw@127.0.0.1:{closed_port()}"
    junk_url = "vless://not-parseable"
    kept, dropped = pf.prefilter(
        [dead_url, open_url, udp_url, junk_url], timeout=1, attempts=1, workers=8
    )
    assert kept == [open_url, udp_url, junk_url]  # order preserved
    assert dropped == [dead_url]


def test_shared_endpoint_is_probed_once(monkeypatch, listener):
    calls = []
    real = socket.create_connection

    def spy(addr, *a, **k):
        calls.append(addr)
        return real(addr, *a, **k)

    monkeypatch.setattr(pf.socket, "create_connection", spy)
    urls = [f"vless://id{i}@127.0.0.1:{listener}?type=ws" for i in range(20)]
    kept, dropped = pf.prefilter(urls, timeout=1)
    assert len(kept) == 20 and not dropped and len(calls) == 1


def test_timeout_gets_a_second_attempt_but_refusal_does_not(monkeypatch):
    attempts = []

    def make(exc):
        def fake(addr, timeout=None):
            attempts.append(addr)
            raise exc

        return fake

    monkeypatch.setattr(pf.socket, "create_connection", make(TimeoutError()))
    assert not pf._tcp_ok("h", 1, 0.1, 2) and len(attempts) == 2
    attempts.clear()
    monkeypatch.setattr(pf.socket, "create_connection", make(ConnectionRefusedError()))
    assert not pf._tcp_ok("h", 1, 0.1, 2) and len(attempts) == 1


def test_cancelled_prefilter_does_not_claim_anything_is_dead():
    cancel = threading.Event()
    cancel.set()
    urls = [f"vless://id@127.0.0.1:{closed_port()}?type=ws"]
    assert pf.prefilter(urls, timeout=1, cancel=cancel) == (urls, [])


def test_fd_limit_clamp():
    assert pf.max_workers_for_fds(1) == 1


def test_identity_ignores_names_only():
    a = vmess("h", 443)
    b = (
        "vmess://"
        + base64.b64encode(
            json.dumps({"id": "x", "add": "h", "port": "443", "ps": "other", "v": "2"}).encode()
        ).decode()
    )
    assert proxy_identity(a) == proxy_identity(b)
    assert proxy_identity("vless://a@h:1#x") == proxy_identity("vless://a@h:1#y")
    assert proxy_identity("vless://a@h:1#x") != proxy_identity("vless://a@h:2#x")
    assert dedupe_proxies(["vless://a@h:1#x", "vless://a@h:1#y", "vless://b@h:1"]) == [
        "vless://a@h:1#x",
        "vless://b@h:1",
    ]


def test_fd_limit_is_raised_towards_hard_limit_before_clamping(monkeypatch):
    calls = []
    state = {"soft": 1024}

    monkeypatch.setattr(pf.resource, "getrlimit", lambda _r: (state["soft"], 1_000_000))

    def setr(_r, limits):
        calls.append(limits)
        state["soft"] = limits[0]

    monkeypatch.setattr(pf.resource, "setrlimit", setr)
    assert pf.max_workers_for_fds(2000) == 2000  # soft 1024 -> raised to 2128
    assert calls == [(2128, 1_000_000)]


def test_fd_limit_clamps_when_it_cannot_be_raised(monkeypatch):
    monkeypatch.setattr(pf.resource, "getrlimit", lambda _r: (1024, 1024))
    monkeypatch.setattr(pf.resource, "setrlimit", lambda *_: (_ for _ in ()).throw(OSError()))
    assert pf.max_workers_for_fds(2000) == 1024 - 128


def test_defaults_are_one_attempt_and_workers_from_the_link():
    import inspect

    sig = inspect.signature(pf.prefilter).parameters
    assert sig["attempts"].default == 1 and sig["workers"].default is None


@pytest.mark.parametrize(
    ("ok_low", "ok_high", "narrow"),
    [(150, 140, False), (150, 130, False), (150, 100, True), (150, 30, True), (0, 0, False)],
)
def test_link_is_narrow_compares_connect_rates(ok_low, ok_high, narrow):
    assert pf.link_is_narrow(ok_low, 300, ok_high, 300) is narrow


def test_pick_workers_is_narrow_without_enough_endpoints_to_calibrate():
    assert pf.pick_workers([("192.0.2.1", 1)] * 10, timeout=0.1) == pf.NARROW_WORKERS


def test_pick_workers_goes_narrow_when_bursts_lose_connects(monkeypatch):
    import threading

    probes = [(f"192.0.2.{i % 250}", 1000 + i) for i in range(2000)]
    in_flight, peak, lock = 0, 0, threading.Lock()

    def lossy(host, port, timeout, attempts):
        nonlocal in_flight, peak
        with lock:
            in_flight += 1
            peak = max(peak, in_flight)
            burst = in_flight > 100
        try:
            threading.Event().wait(0.02)
            return not burst
        finally:
            with lock:
                in_flight -= 1

    monkeypatch.setattr(pf, "_tcp_ok", lossy)
    assert pf.pick_workers(probes, timeout=0.1) == pf.NARROW_WORKERS
    assert peak > 100


def test_pick_workers_stays_wide_when_bursts_are_fine(monkeypatch):
    probes = [(f"192.0.2.{i % 250}", 1000 + i) for i in range(2000)]
    monkeypatch.setattr(pf, "_tcp_ok", lambda *_a: True)
    assert pf.pick_workers(probes, timeout=0.1) == pf.WIDE_WORKERS


@pytest.mark.parametrize("host", ["a" * 70 + ".example.com", "a..example.com"])
def test_undialable_hostname_is_dead_not_a_crash(host):
    """getaddrinfo raises UnicodeError (not OSError) for idna-invalid labels."""
    assert pf._tcp_ok(host, 443, 0.1, 1) is False
