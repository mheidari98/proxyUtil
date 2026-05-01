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
from pathlib import Path

import requests

from .os_glue import chmodX, get_arch, get_OS
from .parsers import parseContent
from .schemes import proxyScheme
from .utils import getSHA256

__all__ = [
    "IP_API_URL",
    "PROXIES",
    "ScrapURL",
    "downloadSingBox",
    "downloadZray",
    "getIP",
    "getIPnCountry",
    "is_alive",
]

PROXIES = {"http": "socks5h://127.0.0.1:{LOCAL_PORT}", "https": "socks5h://127.0.0.1:{LOCAL_PORT}"}
IP_API_URL = "http://ip-api.com/json/"


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


def ScrapURL(url, patterns=proxyScheme):
    """Fetch *url* and return proxy strings extracted from the response body."""
    try:
        res = requests.get(url, timeout=4)
    except Exception:
        logging.debug("Exception occurred", exc_info=True)
        logging.error(f"Can't reach {url}")
        return []

    if res.status_code // 100 != 2:
        logging.error(f"Can't get {url} , status code = {res.status_code}")
        return []

    content = res.text.strip().replace("﻿", "")
    newProxy = parseContent(content, patterns)
    logging.info(f"Got {len(newProxy)} new proxy from {url}")
    return newProxy


def downloadZray(acc: str, repo: str) -> None:
    """Download the latest xray/v2ray release zip from GitHub, verify SHA256, extract."""
    tag = requests.get(
        f"https://api.github.com/repos/{acc}/{repo}-core/releases/latest"
    ).json()["tag_name"]
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
    tag = requests.get(
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    ).json()["tag_name"]
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
