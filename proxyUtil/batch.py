"""Batch validation: find the configs a core will reject before starting it.

A batch process holds many outbounds, and one bad outbound would stop all of them from
starting. We ask the core to validate the config first (`xray run -test`,
`sing-box check`, ...), and if it fails, bisect to isolate the offenders.
"""

from __future__ import annotations

import re
import subprocess

from .cores import CoreSpec

__all__ = ["check_config", "validate_items"]

CHECK_TIMEOUT = 30
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

Item = tuple[str, int]  # (proxy url, local port)


def check_config(spec: CoreSpec, binary: str, path: str) -> tuple[bool, str]:
    """Run the core's own config validation. Returns `(ok, last output line)`."""
    assert spec.check_argv is not None
    try:
        res = subprocess.run(
            spec.check_argv(binary, path),
            capture_output=True,
            text=True,
            timeout=CHECK_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return False, f"{type(err).__name__}: {err}"
    if res.returncode == 0:
        return True, ""
    lines = _ANSI.sub("", res.stderr + res.stdout).strip().splitlines()
    return False, lines[-1][-300:] if lines else f"exit {res.returncode}"


def validate_items(
    spec: CoreSpec, binary: str, items: list[Item], directory: str, *, listen: str = "127.0.0.1"
) -> tuple[list[Item], list[tuple[str, str]]]:
    """Split *items* into `(good, bad)`; *bad* holds `(url, reason)`.

    Cost is one check when everything is valid, and about log2(n) checks per bad
    config otherwise."""
    good: list[Item] = []
    bad: list[tuple[str, str]] = []

    def visit(chunk: list[Item]) -> None:
        path, built = spec.write_batch(chunk, directory, listen=listen)
        built_set = set(built)
        bad.extend(
            (url, "could not build a config")
            for i, (url, _port) in enumerate(chunk)
            if i not in built_set
        )
        kept = [chunk[i] for i in built]
        if not kept or path is None:
            return
        ok, reason = check_config(spec, binary, path)
        if ok:
            good.extend(kept)
        elif len(kept) == 1:
            bad.append((kept[0][0], reason))
        else:
            mid = len(kept) // 2
            visit(kept[:mid])
            visit(kept[mid:])

    visit(items)
    return good, bad
