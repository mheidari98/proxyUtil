"""Exit-country lookup through a proxy, and flag emoji. Lookups issue live HTTP.

The country is resolved by asking a trace endpoint *through the proxy*, so it is where
traffic really leaves, not where the server's IP is registered: CDN-fronted configs
would otherwise get the CDN's country. Cloudflare's ``cdn-cgi/trace`` is the primary
(HTTPS, no rate limit, one small request); ip-api is the fallback.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

import requests

__all__ = ["TRACE_URL", "ExitInfo", "flag", "lookup_exit", "parse_trace"]

TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
UNKNOWN_FLAG = "\N{WAVING WHITE FLAG}"
_CC = re.compile(r"^[A-Z]{2}$")


@dataclass(frozen=True)
class ExitInfo:
    ip: str
    country_code: str | None
    country: str | None = None


def flag(country_code: str | None) -> str:
    """Flag emoji for an ISO 3166-1 alpha-2 code; a white flag when unknown/invalid.

    Cloudflare reports `XX` (unknown) and `T1` (Tor); neither is a country."""
    code = (country_code or "").upper()
    if not _CC.match(code) or code == "XX":
        return UNKNOWN_FLAG
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def parse_trace(text: str) -> dict[str, str]:
    """`key=value` lines of a cdn-cgi/trace body."""
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def _from_trace(proxies, timeout, trace_url) -> ExitInfo | None:
    try:
        res = requests.get(trace_url, proxies=proxies, timeout=timeout)
        res.raise_for_status()
    except requests.RequestException:
        return None
    fields = parse_trace(res.text)
    ip = fields.get("ip")
    if not ip:
        return None
    loc = fields.get("loc", "").upper()
    return ExitInfo(ip, loc if _CC.match(loc) and loc != "XX" else None)


def lookup_exit(
    proxies: dict[str, str],
    timeout: float = 3.0,
    *,
    trace_url: str = TRACE_URL,
    fallback: Callable[..., tuple] | None = None,
) -> ExitInfo | None:
    """Exit IP and country as seen through *proxies*; None if every source failed.

    *fallback* is `(proxies, timeout) -> (ip, country, code)` (default: ip-api)."""
    if (info := _from_trace(proxies, timeout, trace_url)) is not None:
        return info
    if fallback is None:
        from .net import getIPnCountry as fallback
    ip, country, code = fallback(proxies, timeout)
    return ExitInfo(ip, code, country) if ip else None
