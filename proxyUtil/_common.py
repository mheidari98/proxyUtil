"""Internal CLI helpers shared across proxyUtil entry points."""

from __future__ import annotations

import logging
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
    parser.add_argument("--url", help="get proxy from url")
    parser.add_argument("--free", help="get free proxy", action="store_true")
    parser.add_argument("--stdin", help="get proxy from stdin", action="store_true")
    if with_reuse:
        parser.add_argument("--reuse", help="reuse last checked proxy", action="store_true")


def collect_proxies(args, *, free_url: str, patterns=None, output_path: str | None = None):
    """Aggregate proxies from `-f/--url/--stdin/--free/--reuse` into a deduped list."""
    from .net import ScrapURL
    from .parsers import parseContent

    output_path = output_path if output_path is not None else getattr(args, "output", None)
    scrap_extra = (patterns,) if patterns else ()
    parse_extra = (patterns,) if patterns else ()

    lines: set[str] = set()

    if args.file and (fp := Path(args.file)).is_file():
        lines.update(parseContent(fp.read_text(encoding="UTF-8").strip(), *parse_extra))
        logging.info(f"got {len(lines)} from reading proxy from file")

    if getattr(args, "reuse", False) and output_path and (op := Path(output_path)).is_file():
        lines.update(parseContent(op.read_text(encoding="UTF-8").strip(), *parse_extra))

    if args.url:
        lines.update(ScrapURL(args.url, *scrap_extra))

    if args.free:
        lines.update(ScrapURL(free_url, *scrap_extra))

    if args.stdin:
        lines.update(parseContent(sys.stdin.read(), *parse_extra))

    return list(lines)


def find_free_ports(start_port: int, n: int) -> list[int]:
    """Return `n` consecutive free local TCP ports starting at `start_port`."""
    from .os_glue import is_port_in_use

    ports: list[int] = []
    port = start_port
    while len(ports) < n:
        if not is_port_in_use(port):
            ports.append(port)
        port += 1
    return ports
