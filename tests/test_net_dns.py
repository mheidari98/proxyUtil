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
    assert stats == {"lookups": 2, "failed": 2, "pending": 2, "poisoned": 0}
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


def test_deadline_is_a_stall_limit_not_a_total(monkeypatch):
    """Slow but steady answers must not be cut off by the deadline."""

    def slow(host, *_a, **_k):
        time.sleep(0.15)
        return [(socket.AF_INET, 0, 0, "", ("192.0.2.1", 0))]

    monkeypatch.setattr(net.socket, "getaddrinfo", slow)
    names = [f"h{i}.example" for i in range(12)]
    out = net.resolve_hosts(names, deadline=0.5, workers=2)
    assert all(out[n] == ["192.0.2.1"] for n in names)  # 12 x 0.15 / 2 = 0.9 s > 0.5 s


def test_auto_asks_public_resolvers_first_then_system_for_unanswered_names(monkeypatch):
    monkeypatch.setattr(net, "AUTO_RESOLVERS", ("203.0.113.1",))
    asked = []

    def system(host, *_a, **_k):
        asked.append(("system", host))
        if host == "inside.example":
            return [(socket.AF_INET, 0, 0, "", ("10.1.2.3", 0))]
        raise socket.gaierror

    def fake_udp(req, where, timeout=None):
        name = str(req.question[0].name).rstrip(".")
        asked.append((where, name))
        if name == "inside.example":
            raise TimeoutError  # no public resolver answered
        res = net.dns.message.make_response(req)
        if name == "public.example" and req.question[0].rdtype == net.dns.rdatatype.A:
            res.answer.append(
                net.dns.rrset.from_text(req.question[0].name, 60, "IN", "A", "93.184.216.34")
            )
        return res, False

    monkeypatch.setattr(net.socket, "getaddrinfo", system)
    monkeypatch.setattr(net.dns.query, "udp_with_fallback", fake_udp)
    stats = {}
    out = net.resolve_hosts(["public.example", "inside.example", "nx.example"], stats=stats)
    assert out == {
        "public.example": ["93.184.216.34"],
        "inside.example": ["10.1.2.3"],
        "nx.example": None,
    }
    assert ("system", "public.example") not in asked  # resolved publicly: not asked again
    assert ("system", "inside.example") in asked
    assert ("system", "nx.example") not in asked  # a resolver said it does not exist
    assert stats == {"lookups": 3, "failed": 1, "pending": 0, "poisoned": 0}


def test_auto_gives_up_on_public_resolvers_that_never_answer(monkeypatch):
    monkeypatch.setattr(net, "AUTO_RESOLVERS", ("203.0.113.1",))
    calls = []

    def silent(req, where, timeout=None):
        calls.append(where)
        raise TimeoutError

    monkeypatch.setattr(net.dns.query, "udp_with_fallback", silent)
    monkeypatch.setattr(
        net.socket, "getaddrinfo", lambda *_a, **_k: [(socket.AF_INET, 0, 0, "", ("192.0.2.9", 0))]
    )
    names = [f"h{i}.example" for i in range(200)]
    out = net.resolve_hosts(names, workers=1)
    assert all(out[n] == ["192.0.2.9"] for n in names)  # fell back to the system resolver
    assert len(calls) <= 25  # circuit breaker after ~20 unanswered queries


def test_system_keyword_skips_public_resolvers(monkeypatch):
    monkeypatch.setattr(net, "AUTO_RESOLVERS", ("203.0.113.1",))
    monkeypatch.setattr(net.dns.query, "udp_with_fallback", lambda *a, **k: 1 / 0)
    monkeypatch.setattr(
        net.socket, "getaddrinfo", lambda *_a, **_k: [(socket.AF_INET, 0, 0, "", ("192.0.2.9", 0))]
    )
    assert net.resolve_hosts(["a.example"], dns_server="system") == {"a.example": ["192.0.2.9"]}


def test_auto_treats_private_answers_as_dns_filtering_and_does_not_retry_them(monkeypatch):
    monkeypatch.setattr(net, "AUTO_RESOLVERS", ("203.0.113.1",))
    asked = []

    def fake_udp(req, where, timeout=None):
        res = net.dns.message.make_response(req)
        if req.question[0].rdtype == net.dns.rdatatype.A:
            res.answer.append(
                net.dns.rrset.from_text(req.question[0].name, 60, "IN", "A", "10.10.34.35")
            )
        return res, False

    monkeypatch.setattr(net.dns.query, "udp_with_fallback", fake_udp)
    monkeypatch.setattr(net.socket, "getaddrinfo", lambda host, *_a, **_k: asked.append(host))
    stats = {}
    out = net.resolve_hosts(["youtube.example"], stats=stats)
    assert out == {"youtube.example": None}
    assert asked == []  # the system resolver would return the same injected address
    assert stats["poisoned"] == 1 and stats["failed"] == 1


def test_auto_does_not_retry_names_the_public_resolver_says_do_not_exist(monkeypatch):
    monkeypatch.setattr(net, "AUTO_RESOLVERS", ("203.0.113.1",))
    asked = []
    monkeypatch.setattr(
        net.dns.query,
        "udp_with_fallback",
        lambda req, *_a, **_k: (net.dns.message.make_response(req), False),
    )
    monkeypatch.setattr(net.socket, "getaddrinfo", lambda host, *_a, **_k: asked.append(host))
    assert net.resolve_hosts(["gone.example"]) == {"gone.example": None}
    assert asked == []


def test_nxdomain_is_not_asked_again_for_aaaa(monkeypatch):
    asked = []

    def fake_udp(req, where, timeout=None):
        asked.append(req.question[0].rdtype)
        res = net.dns.message.make_response(req)
        res.set_rcode(net.dns.rcode.NXDOMAIN)
        return res, False

    monkeypatch.setattr(net.dns.query, "udp_with_fallback", fake_udp)
    assert net._lookup_do53("gone.example", "203.0.113.1", 1.0) == []
    assert asked == [net.dns.rdatatype.A]
