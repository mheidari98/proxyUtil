"""Pure helpers with no internal dependencies."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
import uuid
from functools import lru_cache, reduce
from operator import or_
from pathlib import Path

__all__ = [
    "base64Decode",
    "finder",
    "format_geo",
    "generate_uuid",
    "getSHA256",
    "isBase64",
    "is_json",
    "is_truthy",
    "is_valid_uuid",
    "mergeMultiDicts",
    "silentremove",
    "split2Npart",
    "split_csv",
]

_UUID_NS = uuid.UUID("00000000-0000-0000-0000-000000000000")
_TRUTHY = {"1", "true", "yes"}


def split2Npart(a, n):
    k, m = divmod(len(a), n)
    return (a[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(n))


def mergeMultiDicts(*dicts):
    return reduce(or_, dicts, {})


def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError:
        return False
    return True


def isBase64(sb):
    try:
        if isinstance(sb, str):
            sb_bytes = sb.encode("ascii")
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        sb_bytes += b"=" * (-len(sb_bytes) % 4)
        if b"-" in sb_bytes or b"_" in sb_bytes:
            return base64.urlsafe_b64encode(base64.urlsafe_b64decode(sb_bytes)) == sb_bytes
        return base64.b64encode(base64.b64decode(sb_bytes).decode().encode()) == sb_bytes
    except Exception:
        return False


def base64Decode(decodedStr):
    urlsafe = "-" in decodedStr or "_" in decodedStr
    decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    return decoder(decodedStr + "=" * (-len(decodedStr) % 4)).decode("utf-8")


def is_valid_uuid(val):
    try:
        uuid.UUID(val)
    except ValueError:
        return False
    return True


def generate_uuid(basedata):
    return str(uuid.uuid5(_UUID_NS, basedata))


def getSHA256(fileName):
    return hashlib.sha256(Path(fileName).read_bytes()).hexdigest()


@lru_cache(maxsize=64)
def _finder_re(spliter):
    return re.compile(rf"\s+{re.escape(spliter)}\s+(\S+)")


def finder(cmd, spliter):
    m = _finder_re(spliter).search(cmd)
    if not m:
        raise ValueError(f"flag {spliter!r} not found in: {cmd!r}")
    return m.group(1)


def silentremove(filename):
    with contextlib.suppress(OSError):
        Path(filename).unlink()


def split_csv(value):
    return [a for a in value.split(",") if a] if value else []


def is_truthy(value):
    return str(value).lower() in _TRUTHY


def format_geo(ip, country, country_code):
    label = f"{country_code} ({country})" if country_code else country
    return f"ip={ip} @ {label}"
