"""Throughput and latency measurement through a local SOCKS port. Live HTTP at call time.

Endpoints follow the speed.cloudflare.com convention (`/__down?bytes=N`, `/__up`) so any
server that mimics them works, including a local one in tests.
"""

from __future__ import annotations

import itertools
import statistics
import time
from dataclasses import dataclass

import requests

__all__ = [
    "SPEEDTEST_BASE",
    "LatencyStats",
    "measure_download",
    "measure_latency",
    "measure_upload",
]

SPEEDTEST_BASE = "https://speed.cloudflare.com"
_CHUNK = 64 * 1024


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


def measure_download(
    proxies: dict[str, str],
    *,
    base: str = SPEEDTEST_BASE,
    max_seconds: float = 8.0,
    max_bytes: int = 20 * 1024 * 1024,
    timeout: float = 5.0,
) -> float | None:
    """Download Mbps, counted from the first byte so connection setup isn't charged to
    throughput. Stops at *max_seconds* or *max_bytes*. None on failure."""
    try:
        with requests.get(
            f"{base}/__down",
            params={"bytes": max_bytes},
            proxies=proxies,
            stream=True,
            timeout=timeout,
        ) as res:
            res.raise_for_status()
            received = 0
            started = None
            for chunk in res.iter_content(_CHUNK):
                now = time.perf_counter()
                if started is None:
                    started = now  # first byte: the clock starts here
                    continue
                received += len(chunk)
                if now - started >= max_seconds or received + _CHUNK >= max_bytes:
                    break
            end = time.perf_counter()
    except requests.RequestException:
        return None
    if started is None or received == 0 or end <= started:
        return None
    return round(received * 8 / (end - started) / 1e6, 2)


def measure_upload(
    proxies: dict[str, str],
    *,
    base: str = SPEEDTEST_BASE,
    max_seconds: float = 6.0,
    max_bytes: int = 10 * 1024 * 1024,
    timeout: float = 5.0,
) -> float | None:
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
        res.raise_for_status()
    except requests.RequestException:
        return None
    elapsed = time.perf_counter() - started
    if sent == 0 or elapsed <= 0:
        return None
    return round(sent * 8 / elapsed / 1e6, 2)
