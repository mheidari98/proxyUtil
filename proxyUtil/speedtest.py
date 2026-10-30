"""Throughput and latency measurement through a local SOCKS port. Live HTTP at call time.

Endpoints follow the speed.cloudflare.com convention (`/__down?bytes=N`, `/__up`) so any
server that mimics them works, including a local one in tests.
"""

from __future__ import annotations

import itertools
import statistics
import time
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

import requests

__all__ = [
    "FALLBACK_DOWNLOADS",
    "SPEEDTEST_BASE",
    "LatencyStats",
    "Transfer",
    "download_urls",
    "measure_download",
    "measure_download_any",
    "measure_latency",
    "measure_upload",
]

SPEEDTEST_BASE = "https://speed.cloudflare.com"
FALLBACK_DOWNLOADS = (
    "https://proof.ovh.net/files/10Mb.dat",
    "http://cachefly.cachefly.net/10mb.test",
)
_CHUNK = 64 * 1024
MIN_BYTES = 128 * 1024  # less than this isn't a throughput measurement
# First byte through a free proxy often takes 5-6 s, so the read timeout must be generous.
TIMEOUT = (10.0, 10.0)


@dataclass(frozen=True)
class Transfer:
    """One throughput attempt: *mbps* is None when it failed, and *error* says why."""

    mbps: float | None
    bytes: int = 0
    error: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class LatencyStats:
    median_ms: float
    jitter_ms: float  # mean absolute difference between consecutive samples
    ok: int
    total: int


def measure_latency(
    url: str, proxies: dict[str, str], samples: int = 5, timeout: float = 3.0
) -> LatencyStats | None:
    """HEAD *url* repeatedly over one kept-alive connection; the first request (which
    pays connection setup) is warm-up and not counted. None if no sample succeeded."""
    times: list[float] = []
    with requests.Session() as session:
        session.proxies.update(proxies)
        for i in range(samples + 1):
            started = time.perf_counter()
            try:
                session.head(url, timeout=timeout, allow_redirects=False)
            except requests.RequestException:
                continue
            if i:  # i == 0 is warm-up
                times.append((time.perf_counter() - started) * 1000)
    if not times:
        return None
    jitter = (
        statistics.fmean(abs(b - a) for a, b in itertools.pairwise(times))
        if len(times) > 1
        else 0.0
    )
    return LatencyStats(round(statistics.median(times), 1), round(jitter, 1), len(times), samples)


def download_urls(base: str, max_bytes: int) -> list[str]:
    """Download sources to try in order. Cloudflare rate-limits (HTTP 429) large downloads
    when many proxies share exit IPs, and some exits black-hole it entirely, so the default
    falls back to other hosts. A custom *base* is used on its own."""
    if base != SPEEDTEST_BASE:
        return [f"{base}/__down?bytes={max_bytes}"]
    return [f"{base}/__down?bytes={max_bytes}", *FALLBACK_DOWNLOADS]


def measure_download(
    proxies: dict[str, str],
    url: str,
    *,
    max_seconds: float = 8.0,
    max_bytes: int = 20 * 1024 * 1024,
    timeout: tuple[float, float] = TIMEOUT,
) -> Transfer:
    """Download Mbps from *url*, counted from the first byte so connection setup isn't
    charged to throughput. Stops at *max_seconds* or *max_bytes*. If the proxy cuts the
    stream after a useful amount of data, the throughput so far is still reported."""
    received = 0
    started = None
    end = time.perf_counter()
    error = None
    try:
        with requests.get(url, proxies=proxies, stream=True, timeout=timeout) as res:
            if res.status_code != 200:
                return Transfer(None, error=f"HTTP {res.status_code}")
            for chunk in res.iter_content(_CHUNK):
                now = time.perf_counter()
                if started is None:
                    started = now  # first byte: the clock starts here
                    continue
                received += len(chunk)
                end = now
                if now - started >= max_seconds or received + _CHUNK >= max_bytes:
                    break
    except requests.RequestException as exc:
        error = _reason(exc)
        end = time.perf_counter()
    if started is None or received < MIN_BYTES or end <= started:
        return Transfer(None, received, error or "no data")
    return Transfer(round(received * 8 / (end - started) / 1e6, 2), received)


def measure_download_any(proxies: dict[str, str], urls: list[str], **kwargs) -> Transfer:
    """First source that yields a speed; otherwise every source's failure reason."""
    reasons = []
    for url in urls:
        result = measure_download(proxies, url, **kwargs)
        if result.mbps is not None:
            return replace(result, source=urlsplit(url).hostname)
        reasons.append(f"{urlsplit(url).hostname}: {result.error}")
    return Transfer(None, error="; ".join(reasons))


def measure_upload(
    proxies: dict[str, str],
    *,
    base: str = SPEEDTEST_BASE,
    max_seconds: float = 6.0,
    max_bytes: int = 10 * 1024 * 1024,
    timeout: tuple[float, float] = TIMEOUT,
) -> Transfer:
    """Upload Mbps over one streamed POST, capped by *max_seconds* / *max_bytes*."""
    sent = 0
    started = time.perf_counter()
    payload = b"\0" * _CHUNK

    def body():
        nonlocal sent
        while sent < max_bytes and time.perf_counter() - started < max_seconds:
            sent += len(payload)
            yield payload

    try:
        res = requests.post(f"{base}/__up", data=body(), proxies=proxies, timeout=timeout)
        if res.status_code != 200:
            return Transfer(None, sent, f"HTTP {res.status_code}")
    except requests.RequestException as exc:
        return Transfer(None, sent, _reason(exc))
    elapsed = time.perf_counter() - started
    if sent < MIN_BYTES or elapsed <= 0:
        return Transfer(None, sent, "no data")
    return Transfer(round(sent * 8 / elapsed / 1e6, 2), sent)


def _reason(exc: BaseException) -> str:
    from .probe import _describe

    text = _describe(exc)
    if "Timeout" in text or "timed out" in text:
        return "timeout"
    return text[:80]
