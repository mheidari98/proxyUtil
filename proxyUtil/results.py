"""Check results and the sink that writes them: crash-safe, optionally streaming.

Also output formats (txt / json / base64 subscription / sing-box client config), the
opt-in tag renamer, and the resume journal.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .geo import flag
from .parsers import proxy_identity, proxy_name, tagChanger

__all__ = [
    "DEFAULT_RENAME",
    "FORMATS",
    "LIVE",
    "SORTS",
    "Journal",
    "Result",
    "ResultSink",
    "format_paths",
    "make_renamer",
    "write_formats",
]

LIVE = "live"
SORTS = ("latency", "country", "scheme", "speed")
FORMATS = ("txt", "json", "b64", "singbox")
DEFAULT_RENAME = "{flag} {cc} {ms}ms | {name}"


@dataclass(frozen=True)
class Result:
    """Outcome for one proxy URL. ``status`` is one of live, dead, config_error,
    unsupported, unreachable, error."""

    url: str
    status: str
    latency_ms: int = 0
    exit_ip: str | None = None
    country: str | None = None
    country_code: str | None = None
    error: str | None = None
    jitter_ms: float | None = None
    down_mbps: float | None = None
    up_mbps: float | None = None


class _Blank(dict):
    def __missing__(self, key):  # unknown {placeholders} render empty instead of raising
        return ""


def make_renamer(template: str) -> Callable[[Result], str]:
    """Build `Result -> url` that rewrites the proxy's display name from *template*.

    Placeholders: {flag} {cc} {country} {ms} {name} {scheme}. Schemes with no name slot
    (naive) keep their URL unchanged."""

    def rename(result: Result) -> str:
        fields = _Blank(
            flag=flag(result.country_code),
            cc=result.country_code or "??",
            country=result.country or "",
            ms=result.latency_ms,
            name=proxy_name(result.url),
            scheme=urlsplit(result.url).scheme,
        )
        try:
            return tagChanger(result.url, template.format_map(fields))
        except Exception:
            return result.url

    return rename


def _sort_key(sort: str) -> Callable[[Result], tuple]:
    match sort:
        case "country":
            return lambda r: (r.country_code is None, r.country_code or "", r.latency_ms)
        case "scheme":
            return lambda r: (urlsplit(r.url).scheme, r.latency_ms)
        case "speed":
            return lambda r: (-(r.down_mbps or 0.0), r.latency_ms)
        case _:
            return lambda r: (r.latency_ms,)


class ResultSink:
    """Collects live results and writes them sorted.

    Default: nothing hits disk until :meth:`finalize`, which writes atomically
    (tmp file + ``os.replace``) so an interrupted write never corrupts a previous file.
    ``live=True`` additionally appends each new live URL the moment it is found
    (flushed, optionally fsynced), then rewrites the file sorted at the end.
    ``path == "-"`` targets stdout. *countries* keeps only results exiting there,
    *limit* keeps the N best in the final output, *rename* maps a result to the line
    written.
    """

    def __init__(
        self,
        path: str,
        *,
        live: bool = False,
        fsync: bool = False,
        limit: int | None = None,
        sort: str = "latency",
        countries: frozenset[str] | None = None,
        rename: Callable[[Result], str] | None = None,
    ):
        self.path = path
        self.live = live
        self.fsync = fsync
        self.limit = limit  # keep only the N best results in the final output
        self.sort = sort
        self.countries = countries
        self.rename = rename
        self._stdout = path == "-"
        self._seen: dict[str, Result] = {}
        self._fh = None
        if live and not self._stdout:
            self._fh = Path(path).open("w", encoding="utf-8")  # noqa: SIM115 - held open

    def line(self, result: Result) -> str:
        return self.rename(result) if self.rename else result.url

    def add(self, result: Result) -> bool:
        """Record a live result. Returns False for non-live, filtered or duplicate URLs."""
        if result.status != LIVE or result.url in self._seen:
            return False
        if self.countries and (result.country_code or "").upper() not in self.countries:
            return False
        self._seen[result.url] = result
        if self.live:
            text = f"{self.line(result)}\n"
            if self._stdout:
                sys.stdout.write(text)
                sys.stdout.flush()
            elif self._fh is not None:
                self._fh.write(text)
                self._fh.flush()
                if self.fsync:
                    os.fsync(self._fh.fileno())
        return True

    def all(self) -> list[Result]:
        """Every stored result, in discovery order (not sorted, not limited)."""
        return list(self._seen.values())

    def update(self, result: Result) -> None:
        """Replace a stored result with an enriched copy (e.g. after a speed test)."""
        if result.url in self._seen:
            self._seen[result.url] = result

    @property
    def count(self) -> int:
        return len(self._seen)

    def ranked(self) -> list[Result]:
        ranked = sorted(self._seen.values(), key=_sort_key(self.sort))
        return ranked[: self.limit] if self.limit else ranked

    def sorted_urls(self) -> list[str]:
        return [r.url for r in self.ranked()]

    def finalize(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        body = "".join(f"{self.line(r)}\n" for r in self.ranked())
        if self._stdout:
            if not self.live:  # already streamed otherwise
                sys.stdout.write(body)
                sys.stdout.flush()
            return
        _atomic_write(Path(self.path), body)


def _atomic_write(target: Path, body: str) -> None:
    tmp = target.with_name(f"{target.name}.tmp")
    try:
        tmp.write_text(body, encoding="utf-8")
        os.replace(tmp, target)
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()


def _singbox_client_config(results: list[Result], line: Callable[[Result], str]) -> dict:
    """A ready-to-import sing-box client: every live proxy as an outbound, an
    auto-selecting `urltest` group and a manual `select` group, behind a local mixed port."""
    from .singbox import build_singbox_config

    outbounds, tags = [], []
    for i, r in enumerate(results):
        built = build_singbox_config(r.url, 0)
        if built is None:
            continue
        outbound = built["outbounds"][0]
        name = proxy_name(line(r)) or proxy_name(r.url) or outbound["server"]
        outbound["tag"] = f"{i + 1:03d} {name}"[:80]
        outbounds.append(outbound)
        tags.append(outbound["tag"])
    groups = (
        [
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
            },
            {"type": "selector", "tag": "proxy", "outbounds": ["auto", *tags], "default": "auto"},
        ]
        if tags
        else []
    )
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
        "outbounds": [*groups, *outbounds, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy" if tags else "direct"},
    }


def format_paths(output: str, formats: list[str]) -> dict[str, Path]:
    """Where each extra format lands, derived from the `-o` path."""
    base = Path(output)
    paths = {
        "json": base.with_suffix(".json"),
        "b64": base.with_suffix(".b64"),
        "singbox": base.with_name(f"{base.stem}.singbox.json"),
    }
    return {fmt: path for fmt, path in paths.items() if fmt in formats}


def write_formats(
    results: list[Result],
    output: str,
    formats: list[str],
    line: Callable[[Result], str] = lambda r: r.url,
) -> list[Path]:
    """Write the extra formats next to *output*; `txt` is the sink's own file.

    json -> `<stem>.json`, b64 -> `<stem>.b64`, singbox -> `<stem>.singbox.json`."""
    paths = format_paths(output, formats)
    written = []
    if "json" in paths:
        path = paths["json"]
        rows = [{**asdict(r), "line": line(r), "name": proxy_name(r.url)} for r in results]
        _atomic_write(path, json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
        written.append(path)
    if "b64" in paths:
        path = paths["b64"]
        blob = base64.b64encode("".join(f"{line(r)}\n" for r in results).encode()).decode()
        _atomic_write(path, blob + "\n")
        written.append(path)
    if "singbox" in paths:
        path = paths["singbox"]
        _atomic_write(
            path, json.dumps(_singbox_client_config(results, line), indent=2, ensure_ascii=False)
        )
        written.append(path)
    return written


class Journal:
    """Append-only record of every tested proxy so an interrupted run can ``--resume``.

    One JSON object per line; live results keep their URL and data so they can be
    restored. Removed after a run completes."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._fh = None

    def load(self) -> tuple[set[str], list[Result]]:
        """`(tested identities, live results)`; tolerant of a torn last line."""
        tested: set[str] = set()
        live: list[Result] = []
        if not self.path.is_file():
            return tested, live
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(raw)
                tested.add(row["id"])
                if row["status"] == LIVE:
                    live.append(Result(**row["result"]))
            except (ValueError, KeyError, TypeError):
                continue
        return tested, live

    def open(self, *, append: bool) -> None:
        self._fh = self.path.open("a" if append else "w", encoding="utf-8")

    def record(self, result: Result) -> None:
        if self._fh is None:
            return
        row: dict = {"id": proxy_identity(result.url), "status": result.status}
        if result.status == LIVE:
            row["result"] = asdict(result)
        self._fh.write(json.dumps(row) + "\n")
        self._fh.flush()

    def close(self, *, remove: bool = False) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        if remove:
            with contextlib.suppress(OSError):
                self.path.unlink()
