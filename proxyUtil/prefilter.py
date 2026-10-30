"""Cheap reachability pre-filter: a TCP connect to each config's server:port.

Most dead subscription entries never answer at all, and starting a core just to wait out
a 3 s probe timeout is by far the most expensive way to learn that. UDP-based schemes
and transports cannot be judged by a TCP connect, so they always pass.
"""

from __future__ import annotations

import contextlib
import json
import logging
import random
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

from .net import resolve_hosts
from .parsers import parse_ss_withPlugin, parse_ssr
from .utils import base64Decode, normalize_network

try:  # POSIX only
    import resource
except ImportError:  # pragma: no cover
    resource = None

__all__ = [
    "link_is_narrow",
    "max_workers_for_fds",
    "needs_tcp_check",
    "pick_workers",
    "prefilter",
    "server_endpoint",
]

UDP_SCHEMES = frozenset({"hysteria", "hysteria2", "hy2", "tuic", "juicity", "wireguard"})
UDP_TRANSPORTS = frozenset({"kcp", "mkcp", "quic"})

WIDE_WORKERS = 2000
NARROW_WORKERS = 50
_LOW_SAMPLE = 300  # endpoints probed at NARROW_WORKERS sockets
_HIGH_SAMPLE = 1200  # probed at 1000 sockets: a burst smaller than ~500 is not lost even on LTE


def server_endpoint(url: str) -> tuple[str, int] | None:
    """`(host, port)` the proxy URL dials, or None if it can't be determined."""
    try:
        loaded = urlparse(url)
        match loaded.scheme:
            case "vmess":
                payload = json.loads(base64Decode(url[8:].split("#", 1)[0]))
                return payload["add"], int(payload["port"])
            case "ss":
                host, port, *_ = parse_ss_withPlugin(url)
                return host, int(port)
            case "ssr":
                parsed = parse_ssr(url)
                return parsed["address"], int(parsed["port"])
            case _:
                if loaded.hostname and loaded.port:
                    return loaded.hostname, loaded.port
    except (ValueError, KeyError, TypeError, AttributeError):
        pass
    return None


def _transport(url: str) -> str:
    loaded = urlparse(url)
    try:
        if loaded.scheme == "vmess":
            return normalize_network(json.loads(base64Decode(url[8:].split("#", 1)[0])).get("net"))
        return normalize_network(parse_qs(loaded.query).get("type", [""])[0])
    except (ValueError, TypeError, AttributeError):
        return "tcp"


def needs_tcp_check(url: str) -> bool:
    """True only when a TCP connect to the server is a valid liveness signal."""
    scheme = urlparse(url).scheme
    return scheme not in UDP_SCHEMES and _transport(url) not in UDP_TRANSPORTS


def max_workers_for_fds(wanted: int, reserve: int = 128) -> int:
    """Clamp *wanted* to the open-file limit so we never die with 'too many open files'.

    Many systems default the soft limit to 1024; raise it towards the hard limit first."""
    if resource is None:
        return wanted
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = wanted + reserve
    if soft != resource.RLIM_INFINITY and soft < target:
        new_soft = target if hard == resource.RLIM_INFINITY else min(target, hard)
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            soft = new_soft
    if soft == resource.RLIM_INFINITY:
        return wanted
    return max(1, min(wanted, soft - reserve))


def _tcp_ok(host: str, port: int, timeout: float, attempts: int) -> bool:
    """Connect check. A refusal is definitive; only timeouts get another attempt."""
    for _ in range(max(1, attempts)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except TimeoutError:
            continue
        except (OSError, UnicodeError):  # UnicodeError: host not idna-encodable (label >63 chars)
            return False
    return False


def link_is_narrow(ok_low: int, n_low: int, ok_high: int, n_high: int) -> bool:
    """True when many sockets at once connect clearly less often than few (lossy access link).

    Measured from an LTE home link: 86% of live servers still answered at 50 sockets, 49% at
    200 and 8% at 2000; on an office line the rate does not depend on the socket count."""
    if not (n_low and n_high and ok_low):
        return False
    return ok_high / n_high < 0.85 * (ok_low / n_low)


def pick_workers(
    probes: list[tuple[str, int]], timeout: float, cancel: threading.Event | None = None
) -> int:
    """`WIDE_WORKERS` or `NARROW_WORKERS`, from the connect rate of two random samples of
    *probes*: one at 50 sockets, one at 1000. Too few endpoints to calibrate: narrow (such a
    list is quick anyway, and a burst of a thousand is already enough to lose connects)."""
    if len(probes) < _LOW_SAMPLE + _HIGH_SAMPLE:
        return NARROW_WORKERS

    def connected(sample, sockets):
        def check(probe):
            return not (cancel and cancel.is_set()) and _tcp_ok(probe[0], probe[1], timeout, 1)

        with ThreadPoolExecutor(max_workers=sockets) as pool:
            return sum(pool.map(check, sample))

    sample = random.sample(probes, _LOW_SAMPLE + _HIGH_SAMPLE)
    low, high = sample[:_LOW_SAMPLE], sample[_LOW_SAMPLE:]
    ok_low, ok_high = connected(low, NARROW_WORKERS), connected(high, 1000)
    narrow = link_is_narrow(ok_low, len(low), ok_high, len(high))
    logging.info(
        f"link: {'narrow' if narrow else 'wide'} (connect rate {ok_low / len(low):.0%} at "
        f"{NARROW_WORKERS} sockets, {ok_high / len(high):.0%} at 1000)"
    )
    return NARROW_WORKERS if narrow else WIDE_WORKERS


def prefilter(
    urls: list[str],
    *,
    workers: int | None = None,
    timeout: float = 2.0,
    attempts: int = 1,
    cancel: threading.Event | None = None,
    dns_deadline: float = 10.0,
    dns_server: str | None = None,
    reasons: dict[str, str] | None = None,
    dns_stats: dict[str, int] | None = None,
) -> tuple[list[str], list[str]]:
    """Split *urls* into `(kept, dropped)`; order is preserved.

    Hostnames are resolved up front, once each, under *dns_deadline* (see `resolve_hosts`),
    so a hung lookup can't stall the run; the connect then goes to the resolved IP. A config
    whose host did not resolve is dropped. If given, *reasons* is filled with
    `url -> "dns" | "tcp"` for every dropped url and *dns_stats* with the lookup counts.

    Measured on 13.8k real configs: a second attempt on timeouts costs ~25 s and recovers
    nothing beyond run-to-run noise, so one attempt is the default.

    *workers* is the number of sockets in flight; None picks it from the link (`pick_workers`):
    a lossy access link drops most connects when too many are tried at once.

    Configs sharing an ip:port are probed once. Anything we cannot judge (UDP,
    unparsable endpoint) is kept."""
    endpoints: dict[str, tuple[str, int] | None] = {
        url: server_endpoint(url) if needs_tcp_check(url) else None for url in urls
    }
    hosts = sorted({ep[0] for ep in endpoints.values() if ep})
    if not hosts:
        return list(urls), []

    resolved = resolve_hosts(
        hosts, deadline=dns_deadline, dns_server=dns_server, cancel=cancel, stats=dns_stats
    )
    if cancel is not None and cancel.is_set():
        return list(urls), []  # shutting down: don't claim anything is dead

    # first address only: resolve_hosts lists IPv4 before IPv6
    probes: dict[str, tuple[str, int] | None] = {
        url: (ips[0], ep[1]) if ep and (ips := resolved[ep[0]]) else None
        for url, ep in endpoints.items()
    }
    unique = sorted({probe for probe in probes.values() if probe})
    alive: dict[tuple[str, int], bool] = {}
    if unique:
        wanted = pick_workers(unique, timeout, cancel) if workers is None else workers
        workers = max_workers_for_fds(min(wanted, len(unique)))
        if workers < min(wanted, len(unique)):
            logging.warning(f"prefilter limited to {workers} sockets by the open-file limit")

        def check(probe):
            if cancel is not None and cancel.is_set():
                return True  # shutting down: don't claim anything is dead
            return _tcp_ok(probe[0], probe[1], timeout, attempts)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            alive = dict(zip(unique, pool.map(check, unique), strict=True))

    kept, dropped = [], []
    for url in urls:
        if endpoints[url] is None:
            kept.append(url)
        elif (probe := probes[url]) is None:
            dropped.append(url)
            if reasons is not None:
                reasons[url] = "dns"
        elif alive[probe]:
            kept.append(url)
        else:
            dropped.append(url)
            if reasons is not None:
                reasons[url] = "tcp"
    return kept, dropped
