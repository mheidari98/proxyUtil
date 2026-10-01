"""Cheap reachability pre-filter: a TCP connect to each config's server:port.

Most dead subscription entries never answer at all, and starting a core just to wait out
a 3 s probe timeout is by far the most expensive way to learn that. UDP-based schemes
and transports cannot be judged by a TCP connect, so they always pass.
"""

from __future__ import annotations

import contextlib
import json
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

from .parsers import parse_ss_withPlugin, parse_ssr
from .utils import base64Decode, normalize_network

try:  # POSIX only
    import resource
except ImportError:  # pragma: no cover
    resource = None

__all__ = ["max_workers_for_fds", "needs_tcp_check", "prefilter", "server_endpoint"]

UDP_SCHEMES = frozenset({"hysteria", "hysteria2", "hy2", "tuic", "juicity", "wireguard"})
UDP_TRANSPORTS = frozenset({"kcp", "mkcp", "quic"})


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
        except OSError:
            return False
    return False


def prefilter(
    urls: list[str],
    *,
    workers: int = 2000,
    timeout: float = 2.0,
    attempts: int = 1,
    cancel: threading.Event | None = None,
) -> tuple[list[str], list[str]]:
    """Split *urls* into `(kept, dropped)`; order is preserved.

    Measured on 13.8k real configs: a second attempt on timeouts costs ~25 s and recovers
    nothing beyond run-to-run noise, so one attempt is the default.

    Configs sharing a server:port are probed once. Anything we cannot judge (UDP,
    unparsable endpoint) is kept."""
    endpoints: dict[str, tuple[str, int] | None] = {
        url: server_endpoint(url) if needs_tcp_check(url) else None for url in urls
    }
    unique = sorted({ep for ep in endpoints.values() if ep})
    if not unique:
        return list(urls), []

    workers = max_workers_for_fds(min(workers, len(unique)))
    if workers < min(2000, len(unique)):
        logging.warning(f"prefilter limited to {workers} sockets by the open-file limit")

    def check(ep):
        if cancel is not None and cancel.is_set():
            return True  # shutting down: don't claim anything is dead
        return _tcp_ok(ep[0], ep[1], timeout, attempts)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        alive = dict(zip(unique, pool.map(check, unique), strict=True))

    kept, dropped = [], []
    for url in urls:
        ep = endpoints[url]
        (kept if ep is None or alive[ep] else dropped).append(url)
    return kept, dropped
