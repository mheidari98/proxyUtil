import socket
import threading
import time

from proxyUtil import net
from proxyUtil import prefilter as pf


def block_forever(*_a, **_k):
    threading.Event().wait()


def test_resolve_hosts_returns_at_deadline_when_getaddrinfo_hangs(monkeypatch):
    monkeypatch.setattr(net.socket, "getaddrinfo", block_forever)
    stats = {}
    started = time.monotonic()
    out = net.resolve_hosts(["a.example", "b.example"], deadline=0.5, stats=stats)
    assert time.monotonic() - started < 3
    assert out == {"a.example": None, "b.example": None}
    assert stats == {"lookups": 2, "failed": 2, "pending": 2}
    # the hung threads are daemons, so they can't keep the interpreter alive
    hung = [t for t in threading.enumerate() if t.name.startswith("resolve-")]
    assert hung and all(t.daemon for t in hung)


def test_unresolved_is_none_and_resolved_prefers_ipv4(monkeypatch):
    def fake(host, *_a, **_k):
        if host == "dual.example":
            return [
                (socket.AF_INET6, 0, 0, "", ("2001:db8::1", 0)),
                (socket.AF_INET, 0, 0, "", ("192.0.2.1", 0)),
                (socket.AF_INET, 0, 0, "", ("192.0.2.1", 0)),
            ]
        raise socket.gaierror("nope")

    monkeypatch.setattr(net.socket, "getaddrinfo", fake)
    out = net.resolve_hosts(["dual.example", "dead.example", "dual.example"], deadline=2)
    assert out == {"dual.example": ["192.0.2.1", "2001:db8::1"], "dead.example": None}


def test_ip_literals_are_not_resolved(monkeypatch):
    monkeypatch.setattr(net.socket, "getaddrinfo", block_forever)
    out = net.resolve_hosts(["1.2.3.4", "[::1]"], deadline=0.5)
    assert out == {"1.2.3.4": ["1.2.3.4"], "[::1]": ["::1"]}


def test_idna_invalid_name_resolves_to_none():
    assert net.resolve_hosts(["a" * 70 + ".example.com"], deadline=2) == {
        "a" * 70 + ".example.com": None
    }


def test_dns_server_path_uses_dnspython(monkeypatch):
    monkeypatch.setattr(net.socket, "getaddrinfo", block_forever)
    seen = []

    def fake_udp(req, where, timeout=None):
        seen.append((where, timeout))
        raise TimeoutError

    monkeypatch.setattr(net.dns.query, "udp_with_fallback", fake_udp)
    out = net.resolve_hosts(["x.example"], deadline=1, dns_server="127.0.0.1")
    assert out == {"x.example": None} and seen and seen[0][0] == "127.0.0.1" and seen[0][1] <= 1


def test_prefilter_drops_unresolved_with_reason_dns(monkeypatch):
    monkeypatch.setattr(net.socket, "getaddrinfo", block_forever)
    dead = "vless://id@nx.example:443?type=ws"
    udp = "hysteria2://pw@nx.example:443"
    reasons, stats = {}, {}
    started = time.monotonic()
    kept, dropped = pf.prefilter(
        [dead, udp], dns_deadline=0.5, timeout=0.5, reasons=reasons, dns_stats=stats
    )
    assert time.monotonic() - started < 3
    assert (kept, dropped) == ([udp], [dead])
    assert reasons == {dead: "dns"} and stats["pending"] == 1
