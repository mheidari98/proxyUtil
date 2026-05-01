"""Network-side-effect helpers: anything in here issues live HTTP/IO at call time.

These are intentionally isolated so callers (and tests) can see at a glance which
utilities hit the network. Never import from a test that doesn't carry the
``@pytest.mark.network`` mark.
"""

from __future__ import annotations

import logging
import os
import sys
import time
import urllib.request
import zipfile

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
    import socket

    try:
        return socket.gethostbyname(domain)
    except Exception:
        return False


def is_alive(testDomain, proxy, timeOut=3):
    try:
        start = time.perf_counter()
        requests.head(testDomain, proxies=proxy, timeout=timeOut)
        end = time.perf_counter()
    except Exception:
        return 0
    return ((end - start) * 100).__round__()


def getIPnCountry(proxy, timeOut):
    try:
        result = requests.get(IP_API_URL, proxies=proxy, timeout=timeOut).json()
        return result["query"], result["country"], result.get("countryCode") or None
    except (requests.RequestException, ValueError, KeyError):
        return None, None, None


def ScrapURL(url, patterns=proxyScheme):
    """Fetch *url* and return proxy strings extracted from the response body."""
    newProxy: list[str] = []
    try:
        res = requests.get(url, timeout=4)
    except Exception:
        logging.debug("Exception occurred", exc_info=True)
        logging.error(f"Can't reach {url}")
        return newProxy

    if (res.status_code // 100) == 2:
        content = res.text.strip().replace("﻿", "")
        newProxy = parseContent(content, patterns)
        logging.info(f"Got {len(newProxy)} new proxy from {url}")
    else:
        logging.error(f"Can't get {url} , status code = {res.status_code}")
    return newProxy


def downloadZray(acc: str, repo: str) -> None:
    """Download the latest xray/v2ray release zip from GitHub, verify SHA256, extract."""
    TAG = requests.get(f"https://api.github.com/repos/{acc}/{repo}-core/releases/latest").json()[
        "tag_name"
    ]
    ZRAY_FILE = f"{repo}-{get_OS()}-{get_arch()}.zip"
    ZRAY_URL = f"https://github.com/{acc}/{repo}-core/releases/download/{TAG}/{ZRAY_FILE}"
    DGST_FILE = f"{ZRAY_FILE}.dgst"
    DGST_URL = f"https://github.com/{acc}/{repo}-core/releases/download/{TAG}/{DGST_FILE}"
    ZIP_FILE = f"{repo}.zip"

    urllib.request.urlretrieve(ZRAY_URL, ZIP_FILE)
    logging.info(f"Downloaded {ZRAY_FILE}")
    r = requests.get(DGST_URL)
    FILE_SHA256 = (
        next(line for line in r.content.splitlines() if line.startswith(b"SHA2-256"))
        .decode()
        .split()[1]
    )
    if getSHA256(ZIP_FILE) != FILE_SHA256:
        logging.error("SHA256 Check failed")
        logging.error(f"Expected: {FILE_SHA256}")
        logging.error(f"Actual: {getSHA256(ZIP_FILE)}")
        sys.exit(1)
    logging.info("SHA256 Check passed")
    with zipfile.ZipFile(ZIP_FILE, "r") as zip_ref:
        zip_ref.extractall(repo)
    os.remove(ZIP_FILE)
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
    url = f"https://github.com/SagerNet/sing-box/releases/download/{tag}/{name}.tar.gz"
    archive = f"{name}.tar.gz"
    urllib.request.urlretrieve(url, archive)
    logging.info(f"Downloaded {archive}")

    import tarfile

    with tarfile.open(archive, "r:gz") as tf:
        tf.extractall("sing-box-tmp")
    binary_src = os.path.join("sing-box-tmp", name, "sing-box")
    if get_OS() == "windows":
        binary_src += ".exe"
    os.makedirs("sing-box", exist_ok=True)
    target = os.path.join("sing-box", os.path.basename(binary_src))
    os.replace(binary_src, target)
    chmodX(target)

    import shutil

    shutil.rmtree("sing-box-tmp", ignore_errors=True)
    os.remove(archive)
