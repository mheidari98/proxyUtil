"""Core registry: lookup binary + scheme support + write_config function by name.

A single ``--core`` flag selects one entry. The chosen core is the only one we
launch; URLs whose scheme isn't in ``core.schemes`` get skipped with a debug log.
sing-box is the unified core (speaks every scheme proxyUtil parses); xray /
v2ray are equivalent and speak the classic vmess/vless/trojan/ss/ssr set.
"""

from __future__ import annotations

import datetime
import itertools
import json
import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import singbox, xray
from .os_glue import augment_local_path
from .parsers import parse_ss_withPlugin
from .utils import base64Decode, is_truthy

__all__ = ["AUTO", "CORE_NAMES", "REGISTRY", "CoreSpec", "get", "pick_auto", "resolve"]

AUTO = "auto"


@dataclass(frozen=True)
class CoreSpec:
    name: str
    binary: str
    schemes: frozenset[str]
    write_config: Callable[..., str | None]  # (url, port, dir, *, listen=...)
    run_argv: Callable[[str, str], list[str]]
    # Reason this core can't run *url* even though it speaks the scheme (None = fine).
    unsupported_reason: Callable[[str], str | None] = field(default=lambda _url: None)
    # (items, *, listen) -> (config dict, indices of items that built); batch mode.
    build_batch: Callable[..., tuple[dict, list[int]]] | None = None
    # (binary, config) -> argv that validates a config and exits 0 when it is acceptable.
    check_argv: Callable[[str, str], list[str]] | None = None

    def write_batch(self, items, directory: str, *, listen: str = "127.0.0.1"):
        """Write one config for all *items*; returns `(path | None, built indices)`."""
        assert self.build_batch is not None
        config, built = self.build_batch(items, listen=listen)
        if not built:
            return None, []
        path = Path(directory) / f"{self.name}_batch_{next(_batch_ids)}.json"
        path.write_text(json.dumps(config))
        return str(path), built


_batch_ids = itertools.count()


def _run_argv(binary, config):
    return [binary, "run", "-c", config]


# Shadowsocks ciphers each core implements (checked against xray 26.3 / v2ray 5.48 with
# `-test`). Legacy stream ciphers (aes-*-cfb, rc4-md5, ...) are in neither: the core exits
# at startup. sing-box supports them.
_V2RAY_SS_METHODS = frozenset(
    {
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-poly1305",
        "chacha20-ietf-poly1305",
        "none",
        "plain",
    }
)
_XRAY_SS_METHODS = _V2RAY_SS_METHODS | {"xchacha20-poly1305", "xchacha20-ietf-poly1305"}


def _ss_method_checker(methods, *, allow_2022):
    def unsupported(url):
        if not url.startswith("ss://"):
            return None
        try:
            method = parse_ss_withPlugin(url)[2].lower()
        except (ValueError, IndexError, AttributeError):
            return None  # let the config builder report the parse error
        if method in methods or (allow_2022 and method.startswith("2022-")):
            return None
        return f"cipher {method} not supported (try -c sing-box)"

    return unsupported


# xray-core refuses `allowInsecure` after this date ("use pinnedPeerCertSha256 instead").
_XRAY_ALLOW_INSECURE_REMOVED = datetime.date(2026, 6, 1)


def _requests_insecure_tls(url):
    """True when the URL asks to skip certificate verification."""
    try:
        if url.startswith("vmess://"):
            body = json.loads(base64Decode(url[8:].split("#", 1)[0]))
            return is_truthy(body.get("allowInsecure")) or is_truthy(body.get("skip-cert-verify"))
        query = {k.lower(): v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        return is_truthy(query.get("allowinsecure")) or is_truthy(query.get("skip-cert-verify"))
    except (ValueError, TypeError, AttributeError):
        return False


def _xray_unsupported(url, _ss=_ss_method_checker(_XRAY_SS_METHODS, allow_2022=True)):
    if reason := _ss(url):
        return reason
    if datetime.date.today() >= _XRAY_ALLOW_INSECURE_REMOVED and _requests_insecure_tls(url):
        return "xray removed allowInsecure on 2026-06-01; cert-skipping config (try -c sing-box)"
    return None


_v2ray_unsupported = _ss_method_checker(_V2RAY_SS_METHODS, allow_2022=False)


REGISTRY: dict[str, CoreSpec] = {
    name: CoreSpec(
        name=name,
        binary=binary,
        schemes=schemes,
        write_config=write_config,
        run_argv=_run_argv,
        unsupported_reason=unsupported,
        build_batch=build_batch,
        check_argv=check_argv,
    )
    for name, binary, schemes, write_config, unsupported, build_batch, check_argv in (
        (
            "xray",
            "xray",
            xray.SCHEMES,
            xray.writeConfig,
            _xray_unsupported,
            xray.createBatchConfig,
            lambda b, c: [b, "run", "-test", "-c", c],
        ),
        (
            "v2ray",
            "v2ray",
            xray.SCHEMES,
            xray.writeConfig,
            _v2ray_unsupported,
            xray.createBatchConfig,
            lambda b, c: [b, "test", "-c", c],
        ),
        (
            "sing-box",
            "sing-box",
            singbox.SCHEMES,
            singbox.writeConfig,
            lambda _url: None,
            singbox.build_singbox_batch,
            lambda b, c: [b, "check", "-c", c],
        ),
    )
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


def pick_auto() -> CoreSpec | None:
    """Best installed core: sing-box (widest coverage), then xray, then v2ray."""
    augment_local_path()
    for name in ("sing-box", "xray", "v2ray"):
        if shutil.which(REGISTRY[name].binary):
            return REGISTRY[name]
    return None


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

    match spec.binary:
        case "v2ray":
            downloadZray("v2fly", "v2ray")
        case "xray":
            downloadZray("XTLS", "xray")
        case "sing-box":
            downloadSingBox()
    return shutil.which(spec.binary)
