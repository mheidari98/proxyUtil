"""Pure helpers with no internal dependencies."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import uuid

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


def split2Npart(a, n):
    k, m = divmod(len(a), n)
    return (a[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(n))


def mergeMultiDicts(*dicts):
    result = {}
    for d in dicts:
        result |= d
    return result


def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError:
        return False
    return True


def isBase64(sb):
    try:
        if isinstance(sb, str):
            sb_bytes = bytes(sb, "ascii")
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        sb_bytes = sb_bytes + b"=" * (-len(sb_bytes) % 4)
        if b"-" in sb_bytes or b"_" in sb_bytes:
            return base64.urlsafe_b64encode(base64.urlsafe_b64decode(sb_bytes)) == sb_bytes
        return base64.b64encode(base64.b64decode(sb_bytes).decode().encode()) == sb_bytes
    except Exception:
        return False


def base64Decode(decodedStr):
    if "-" in decodedStr or "_" in decodedStr:
        return base64.urlsafe_b64decode(decodedStr + "===").decode("utf-8")
    return base64.b64decode(decodedStr + "=" * (-len(decodedStr) % 4)).decode("utf-8")


def is_valid_uuid(val):
    try:
        uuid.UUID(val)
    except ValueError:
        return False
    return True


def generate_uuid(basedata):
    UUID_NAMESPACE = uuid.UUID("00000000-0000-0000-0000-000000000000")
    return str(uuid.uuid5(UUID_NAMESPACE, basedata))


def getSHA256(fileName):
    with open(fileName, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()


def finder(cmd, spliter):
    return re.search(rf"\s+{spliter}\s+(\S+)", cmd).group(1)


def silentremove(filename):
    with contextlib.suppress(OSError):
        os.remove(filename)


def split_csv(value):
    if not value:
        return []
    return [a for a in value.split(",") if a]


def is_truthy(value):
    return str(value).lower() in ("1", "true", "yes")


def format_geo(ip, country, country_code):
    label = f"{country_code} ({country})" if country_code else country
    return f"ip={ip} @ {label}"
