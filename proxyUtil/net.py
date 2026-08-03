"""Network-side-effect helpers: anything in here issues live HTTP/IO at call time.

These are intentionally isolated so callers (and tests) can see at a glance which
utilities hit the network. Never import from a test that doesn't carry the
``@pytest.mark.network`` mark.
"""

from __future__ import annotations

import logging
import shutil
import socket
import sys
import tarfile
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests

from .os_glue import chmodX, get_arch, get_OS
from .parsers import parseContent
from .schemes import proxyScheme
from .utils import getSHA256

__all__ = [
    "IP_API_URL",
    "PROXIES",
    "FetchResult",
    "ScrapURL",
    "ScrapURLs",
    "downloadSingBox",
    "downloadZray",
    "fetchSource",
    "getIP",
    "getIPnCountry",
    "is_alive",
]

PROXIES = {"http": "socks5h://127.0.0.1:{LOCAL_PORT}", "https": "socks5h://127.0.0.1:{LOCAL_PORT}"}
IP_API_URL = "http://ip-api.com/json/"

CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
DEADLINE = 30
MAX_BYTES = 25 * 1024 * 1024
USER_AGENT = "proxyUtil"


def getIP(domain):
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return None


def is_alive(testDomain, proxy, timeOut=3):
    try:
        start = time.perf_counter()
        requests.head(testDomain, proxies=proxy, timeout=timeOut)
        elapsed = time.perf_counter() - start
    except Exception:
        return 0
    return round(elapsed * 100)


def getIPnCountry(proxy, timeOut):
    try:
        result = requests.get(IP_API_URL, proxies=proxy, timeout=timeOut).json()
        return result["query"], result["country"], result.get("countryCode") or None
    except (requests.RequestException, ValueError, KeyError):
        return None, None, None


@dataclass(frozen=True)
class FetchResult:
    """Outcome of one source fetch, including why it failed."""

    url: str
    proxies: tuple[str, ...] = ()
    elapsed_ms: int = 0
    http_status: int | None = None
    bytes_downloaded: int = 0
    error: str | None = None

    @property
    def reachable(self) -> bool:
        return self.error is None and self.http_status is not None

    @property
    def has_proxies(self) -> bool:
        return self.reachable and bool(self.proxies)


def fetchSource(
    url,
    patterns=proxyScheme,
    *,
    connect_timeout=CONNECT_TIMEOUT,
    read_timeout=READ_TIMEOUT,
    deadline=DEADLINE,
    max_bytes=MAX_BYTES,
    user_agent=USER_AGENT,
) -> FetchResult:
    """Fetch one subscription URL under a hard byte cap and wall-clock deadline.

    Per-request timeouts do not bound a server that trickles bytes forever, so
    the body is streamed and both limits are rechecked on every chunk.
    """
    started = time.monotonic()
    downloaded = 0
    status = None
    try:
        with requests.get(
            url,
            allow_redirects=True,
            stream=True,
            timeout=(connect_timeout, read_timeout),
            headers={"User-Agent": user_agent},
        ) as res:
            status = res.status_code
            res.raise_for_status()
            chunks = []
            for chunk in res.iter_content(chunk_size=64 * 1024):
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise RuntimeError(f"body exceeds {max_bytes} bytes")
                if time.monotonic() - started > deadline:
                    raise TimeoutError(f"body exceeds {deadline}s deadline")
                chunks.append(chunk)
            content = b"".join(chunks).decode(res.encoding or "utf-8", errors="replace")
            return FetchResult(
                url=url,
                proxies=tuple(parseContent(content, patterns)),
                elapsed_ms=round((time.monotonic() - started) * 1000),
                http_status=status,
                bytes_downloaded=downloaded,
            )
    except requests.HTTPError:
        error = f"HTTP {status}"
    except (requests.RequestException, RuntimeError, TimeoutError) as exc:
        status, error = None, f"{type(exc).__name__}: {exc}"
    logging.error(f"Can't get {url} : {error}")
    return FetchResult(
        url=url,
        elapsed_ms=round((time.monotonic() - started) * 1000),
        http_status=status,
        bytes_downloaded=downloaded,
        error=error[:500],
    )


def ScrapURL(url, patterns=proxyScheme, **kwargs):
    """Fetch *url* and return proxy strings extracted from the response body."""
    result = fetchSource(url, patterns, **kwargs)
    logging.info(f"Got {len(result.proxies)} new proxy from {url}")
    return list(result.proxies)


def ScrapURLs(urls, patterns=proxyScheme, *, workers=10, **kwargs) -> list[FetchResult]:
    """Fetch many sources concurrently. Results keep the order of *urls*."""
    urls = list(urls)
    if not urls:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(urls))) as pool:
        return list(pool.map(lambda u: fetchSource(u, patterns, **kwargs), urls))


def downloadZray(acc: str, repo: str) -> None:
    """Download the latest xray/v2ray release zip from GitHub, verify SHA256, extract."""
    tag = requests.get(f"https://api.github.com/repos/{acc}/{repo}-core/releases/latest").json()[
        "tag_name"
    ]
    base = f"https://github.com/{acc}/{repo}-core/releases/download/{tag}"
    zip_name = f"{repo}-{get_OS()}-{get_arch()}.zip"
    archive = Path(f"{repo}.zip")

    urllib.request.urlretrieve(f"{base}/{zip_name}", archive)
    logging.info(f"Downloaded {zip_name}")

    dgst = requests.get(f"{base}/{zip_name}.dgst").content.splitlines()
    expected = next(line for line in dgst if line.startswith(b"SHA2-256")).decode().split()[1]
    actual = getSHA256(archive)
    if actual != expected:
        logging.error("SHA256 Check failed")
        logging.error(f"Expected: {expected}")
        logging.error(f"Actual: {actual}")
        sys.exit(1)
    logging.info("SHA256 Check passed")

    with zipfile.ZipFile(archive) as zf:
        zf.extractall(repo)
    archive.unlink()
    chmodX(f"{repo}/{repo}")


def downloadSingBox() -> None:
    """Download the latest sing-box release tarball, extract into ./sing-box/."""
    tag = requests.get("https://api.github.com/repos/SagerNet/sing-box/releases/latest").json()[
        "tag_name"
    ]
    version = tag.lstrip("v")
    arch_map = {"64": "amd64", "32": "386", "arm64-v8a": "arm64", "arm32-v7a": "armv7"}
    sb_arch = arch_map.get(get_arch(), get_arch())
    name = f"sing-box-{version}-{get_OS()}-{sb_arch}"
    archive = Path(f"{name}.tar.gz")

    urllib.request.urlretrieve(
        f"https://github.com/SagerNet/sing-box/releases/download/{tag}/{archive.name}",
        archive,
    )
    logging.info(f"Downloaded {archive.name}")

    tmp = Path("sing-box-tmp")
    with tarfile.open(archive, "r:gz") as tf:
        tf.extractall(tmp)

    binary = "sing-box.exe" if get_OS() == "windows" else "sing-box"
    target_dir = Path("sing-box")
    target_dir.mkdir(exist_ok=True)
    target = target_dir / binary
    (tmp / name / binary).replace(target)
    chmodX(str(target))

    shutil.rmtree(tmp, ignore_errors=True)
    archive.unlink()
