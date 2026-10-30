"""Drop configs whose server never answers a TCP connect from the runner.

A runner outside Iran cannot see everything a client in Iran can: on 2026-10-30, 16 of the
577 endpoints that answered from Iran (2.8%) did not answer from the runner (timeouts and
refusals: allow-listed or geo-fenced servers). So the filter is gentle:

- an endpoint that was already published must fail `MAX_STRIKES` runs in a row to be dropped;
- an endpoint that was not published is dropped on its first failure;
- the unfiltered list is still published as `raw`, for anyone who sees more than we do;
- if the runner itself looks offline, nothing is dropped and no strike is recorded.
"""

from __future__ import annotations

import socket

from .prefilter import needs_tcp_check, prefilter, server_endpoint

__all__ = ["apply_strikes", "endpoint_key", "filter_configs", "probe", "runner_is_online"]

MAX_STRIKES = 3
MIN_OK_RATIO = 0.10  # below this the runner's network, not the servers, is the suspect
CANARIES = (("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443))
WORKERS = 1000
CONNECT_TIMEOUT = 4.0
DNS_DEADLINE = 30.0


def endpoint_key(url: str) -> str | None:
    """`host:port` the URL dials, or None when a TCP connect cannot judge it (UDP, unparsable)."""
    endpoint = server_endpoint(url) if needs_tcp_check(url) else None
    return f"{endpoint[0]}:{endpoint[1]}" if endpoint else None


def runner_is_online(timeout: float = CONNECT_TIMEOUT) -> bool:
    for address in CANARIES:
        try:
            socket.create_connection(address, timeout=timeout).close()
            return True
        except OSError:
            continue
    return False


def probe(urls: list[str]) -> set[str]:
    """Endpoints (`host:port`) that failed DNS or the TCP connect, for the TCP-checkable urls."""
    reasons: dict[str, str] = {}
    prefilter(
        urls,
        workers=WORKERS,
        timeout=CONNECT_TIMEOUT,
        dns_deadline=DNS_DEADLINE,
        reasons=reasons,
    )
    return {key for url in reasons if (key := endpoint_key(url))}


def apply_strikes(
    urls: list[str], failed: set[str], published: set[str], strikes: dict[str, int]
) -> tuple[list[str], dict[str, int]]:
    """`(kept, new_strikes)`; *published* is the set of endpoints in the previous `all`.

    An endpoint keeps a place while it has fewer than `MAX_STRIKES` consecutive failures and
    was published before. *strikes* only holds endpoints that are failing but still listed."""
    new_strikes = {key: strikes.get(key, 0) + 1 for key in failed if key in published}
    dropped = {key for key in failed if key not in published or new_strikes[key] >= MAX_STRIKES}
    kept = [url for url in urls if endpoint_key(url) not in dropped]
    return kept, {key: n for key, n in new_strikes.items() if key not in dropped}


def filter_configs(
    urls: list[str], published: set[str], strikes: dict[str, int]
) -> tuple[list[str], dict[str, int], str]:
    """Run the check. Returns `(kept, strikes, note)`; *note* says why nothing was dropped."""
    if not runner_is_online():
        return urls, strikes, "runner offline: filter skipped"
    failed = probe(urls)
    checkable = {key for url in urls if (key := endpoint_key(url))}
    if checkable and 1 - len(failed) / len(checkable) < MIN_OK_RATIO:
        return urls, strikes, "almost every endpoint failed: filter skipped"
    kept, new_strikes = apply_strikes(urls, failed, published, strikes)
    return kept, new_strikes, ""
