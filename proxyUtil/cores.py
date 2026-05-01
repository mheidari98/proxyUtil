"""Core registry: lookup binary + scheme support + write_config function by name.

A single ``--core`` flag selects one entry. The chosen core is the only one we
launch; URLs whose scheme isn't in ``core.schemes`` get skipped with a debug log.
sing-box is the unified core (speaks every scheme proxyUtil parses); xray /
v2ray are equivalent and speak the classic vmess/vless/trojan/ss/ssr set.
"""

from __future__ import annotations

import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass

from . import singbox, xray
from .os_glue import augment_local_path

__all__ = ["CORE_NAMES", "REGISTRY", "CoreSpec", "get", "resolve"]


@dataclass(frozen=True)
class CoreSpec:
    name: str
    binary: str
    schemes: frozenset[str]
    write_config: Callable[[str, int, str], str | None]
    run_argv: Callable[[str, str], list[str]]


def _xray_argv(binary, config):
    return [binary, "run", "-c", config]


def _singbox_argv(binary, config):
    return [binary, "run", "-c", config]


REGISTRY: dict[str, CoreSpec] = {
    "xray": CoreSpec(
        name="xray",
        binary="xray",
        schemes=xray.SCHEMES,
        write_config=xray.writeConfig,
        run_argv=_xray_argv,
    ),
    "v2ray": CoreSpec(
        name="v2ray",
        binary="v2ray",
        schemes=xray.SCHEMES,
        write_config=xray.writeConfig,
        run_argv=_xray_argv,
    ),
    "sing-box": CoreSpec(
        name="sing-box",
        binary="sing-box",
        schemes=singbox.SCHEMES,
        write_config=singbox.writeConfig,
        run_argv=_singbox_argv,
    ),
}

CORE_NAMES = tuple(REGISTRY)


_INSTALL_HINTS = {
    "v2ray": "https://www.v2fly.org/en_US/guide/install.html",
    "xray": "https://github.com/XTLS/Xray-core#installation",
    "sing-box": "https://sing-box.sagernet.org/installation/",
}


def get(name: str) -> CoreSpec:
    try:
        return REGISTRY[name]
    except KeyError as err:
        raise ValueError(f"unknown core: {name!r}") from err


def resolve(spec: CoreSpec, *, prompt_install: bool = True) -> str | None:
    """Find binary on PATH (after augment); offer to download if missing."""
    augment_local_path()
    binary = shutil.which(spec.binary)
    if binary:
        return binary

    logging.error(f"{spec.binary} not found on PATH")
    logging.error(f"install from {_INSTALL_HINTS.get(spec.binary, spec.binary)}")
    if not prompt_install:
        return None
    if input("download it now? [y/n] ").strip() not in ("yes", "y"):
        return None

    from .net import downloadSingBox, downloadZray

    if spec.binary == "v2ray":
        downloadZray("v2fly", "v2ray")
    elif spec.binary == "xray":
        downloadZray("XTLS", "xray")
    elif spec.binary == "sing-box":
        downloadSingBox()
    return shutil.which(spec.binary)
