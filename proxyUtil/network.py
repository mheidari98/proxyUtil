"""Network-side-effect helpers: anything in here issues live HTTP/IO at call time.

These are intentionally isolated so callers (and tests) can see at a glance which utilities
hit the network. **Never** import these from a test that doesn't carry the
``@pytest.mark.network`` mark.
"""

from __future__ import annotations

import logging
import os
import sys
import urllib.request
import zipfile

import requests

from .myUtil import (
    chmodX,
    get_arch,
    get_OS,
    getSHA256,
    parseContent,
    proxyScheme,
)

__all__ = ["ScrapURL", "downloadZray"]


def ScrapURL(url, patterns=proxyScheme):
    """Fetch *url* and return proxy strings extracted from the response body.

    Performs a live HTTP GET (timeout 4s). Returns an empty list on any error.
    """
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
    if getSHA256(ZIP_FILE) == FILE_SHA256:
        logging.info("SHA256 Check passed")
        with zipfile.ZipFile(ZIP_FILE, "r") as zip_ref:
            zip_ref.extractall(repo)
        os.remove(ZIP_FILE)
        chmodX(f"{repo}/{repo}")
    else:
        logging.error("SHA256 Check failed")
        logging.error(f"Expected: {FILE_SHA256}")
        logging.error(f"Actual: {getSHA256(ZIP_FILE)}")
        sys.exit(1)
