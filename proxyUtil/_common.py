"""Internal CLI helpers shared across proxyUtil entry points."""
from __future__ import annotations

from argparse import ArgumentParser

from . import __version__


def add_version_arg(parser: ArgumentParser) -> None:
    """Register a `--version` flag that prints `<prog> <__version__>` and exits."""
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
