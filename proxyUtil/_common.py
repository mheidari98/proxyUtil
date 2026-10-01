"""Internal CLI helpers shared across proxyUtil entry points."""

from __future__ import annotations

import logging
import socket
import sys
from argparse import ArgumentParser
from pathlib import Path

from . import __version__

__all__ = [
    "add_source_args",
    "add_version_arg",
    "collect_proxies",
    "find_free_ports",
]


def add_version_arg(parser: ArgumentParser) -> None:
    """Register a `--version` flag that prints `<prog> <__version__>` and exits."""
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")


def add_source_args(parser: ArgumentParser, *, with_reuse: bool = True) -> None:
    """Register the proxy-source flags shared by checker CLIs."""
    parser.add_argument("-f", "--file", help="file contain proxy")
    parser.add_argument(
        "--url", action="append", metavar="URL", help="get proxy from url (repeatable)"
    )
    parser.add_argument("--sources", metavar="FILE", help="file with one subscription URL per line")
    parser.add_argument("--free", help="get free proxy", action="store_true")
    parser.add_argument("--stdin", help="get proxy from stdin", action="store_true")
    if with_reuse:
        parser.add_argument("--reuse", help="reuse last checked proxy", action="store_true")


def _source_urls(args, free_url: str) -> list[str]:
    urls = args.url or []
    urls = [urls] if isinstance(urls, str) else list(urls)
    if (sources := getattr(args, "sources", None)) and (sp := Path(sources)).is_file():
        urls += [
            line.strip()
            for line in sp.read_text(encoding="UTF-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if args.free:
        urls.append(free_url)
    return list(dict.fromkeys(urls))


def collect_proxies(args, *, free_url: str, patterns=None, output_path: str | None = None):
    """Aggregate proxies from `-f/--url/--sources/--stdin/--free/--reuse` into a deduped,
    order-preserving list. Remote sources are fetched concurrently and each one's
    outcome is logged, so a dead source is visible rather than silently empty."""
    from .net import ScrapURLs
    from .parsers import parseContent

    output_path = output_path if output_path is not None else getattr(args, "output", None)
    extra = (patterns,) if patterns else ()

    lines: dict[str, None] = {}

    if args.file and (fp := Path(args.file)).is_file():
        lines.update(dict.fromkeys(parseContent(fp.read_text(encoding="UTF-8").strip(), *extra)))
        logging.info(f"got {len(lines)} from reading proxy from file")

    if getattr(args, "reuse", False) and output_path and (op := Path(output_path)).is_file():
        lines.update(dict.fromkeys(parseContent(op.read_text(encoding="UTF-8").strip(), *extra)))

    for res in ScrapURLs(_source_urls(args, free_url), *extra):
        if res.reachable:
            logging.info(f"source {res.url}: {len(res.proxies)} proxies in {res.elapsed_ms} ms")
            lines.update(dict.fromkeys(res.proxies))
        else:
            logging.warning(f"source {res.url}: FAILED ({res.error})")

    if args.stdin:
        lines.update(dict.fromkeys(parseContent(sys.stdin.read(), *extra)))

    return list(lines)


def _can_bind(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def find_free_ports(start_port: int, n: int) -> list[int]:
    """Return `n` free local TCP ports at or above `start_port` (verified by binding)."""
    ports: list[int] = []
    port = start_port
    while len(ports) < n:
        if port > 65535:
            raise RuntimeError(f"ran out of free ports above {start_port}: found {len(ports)}/{n}")
        if _can_bind(port):
            ports.append(port)
        port += 1
    return ports
