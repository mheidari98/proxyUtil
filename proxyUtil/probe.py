"""Liveness probes through a local SOCKS port. These issue live HTTP at call time."""

from __future__ import annotations

import itertools
import statistics
import time
from dataclasses import dataclass

import requests

__all__ = ["ProbeResult", "probe_liveness", "probe_stable", "socks_proxies"]


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    latency_ms: int = 0
    status_code: int | None = None
    error: str | None = None
    jitter_ms: float | None = None


def socks_proxies(port: int, host: str = "127.0.0.1") -> dict[str, str]:
    url = f"socks5h://{host}:{port}"
    return {"http": url, "https": url}


def _root_cause(exc: BaseException) -> BaseException:
    """Unwrap requests/urllib3 wrapper exceptions down to the one that says what failed."""
    for _ in range(8):
        inner = getattr(exc, "reason", None) or exc.__cause__
        if inner is None and exc.args and isinstance(exc.args[0], BaseException):
            inner = exc.args[0]
        if not isinstance(inner, BaseException):
            break
        exc = inner
    return exc


def _describe(exc: Exception) -> str:
    """Short `Class: message` of the root cause; the outer class alone hides why a probe
    failed."""
    root = _root_cause(exc)
    msg = " ".join(str(root).split())
    # urllib3 prefixes "SOCKSConnection(host=..., port=...): " noise: keep the part after it
    msg = msg.split("): ", 1)[-1]
    name = type(root).__name__
    return f"{name}: {msg[:160]}" if msg else name


def _accepts(url: str, status: int) -> bool:
    """`generate_204` style endpoints must answer exactly 204; anything else, 2xx/3xx.

    A bare "got a response" is not liveness: captive portals, block pages and broken
    gateways all answer, with 4xx/5xx or a 200 for the wrong URL."""
    if url.rstrip("/").endswith("generate_204"):
        return status == 204
    return 200 <= status < 400


def probe_liveness(
    url: str, proxies: dict[str, str], timeout: float = 3.0, *, retries: int = 0
) -> ProbeResult:
    """HEAD *url* through *proxies*; latency is reported in real milliseconds.

    *timeout* bounds connect and read separately, so a worst-case probe can take
    up to twice that. A timeout (never a refusal or an error status) is retried up to
    *retries* times; the reported latency is that of the successful attempt."""
    for attempt in range(retries + 1):
        started = time.perf_counter()
        try:
            res = requests.head(url, proxies=proxies, timeout=timeout, allow_redirects=False)
            break
        except requests.Timeout as exc:
            if attempt == retries:
                return ProbeResult(False, error=_describe(exc))
        except requests.RequestException as exc:
            return ProbeResult(False, error=_describe(exc))
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    if not _accepts(url, res.status_code):
        return ProbeResult(False, elapsed_ms, res.status_code, f"HTTP {res.status_code}")
    return ProbeResult(True, elapsed_ms, res.status_code)


def probe_stable(
    first: ProbeResult, url: str, proxies: dict[str, str], timeout: float, samples: int
) -> ProbeResult:
    """Confirm a live *first* probe with extra probes, *samples* in total.

    One miss is tolerated once there are at least 3 samples (networks hiccup); fewer
    samples must all pass. Latency becomes the median and jitter the mean absolute
    difference between consecutive probes."""
    if samples <= 1 or not first.ok:
        return first
    runs = [first] + [probe_liveness(url, proxies, timeout) for _ in range(samples - 1)]
    failed = [r for r in runs if not r.ok]
    if len(failed) > (1 if samples >= 3 else 0):
        return ProbeResult(
            False, error=f"unstable: {len(failed)}/{samples} probes failed ({failed[0].error})"
        )
    times = [r.latency_ms for r in runs if r.ok]
    jitter = (
        statistics.fmean(abs(b - a) for a, b in itertools.pairwise(times)) if len(times) > 1 else 0
    )
    return ProbeResult(
        True, round(statistics.median(times)), first.status_code, jitter_ms=round(jitter, 1)
    )
