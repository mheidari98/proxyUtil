"""URL parsers for every supported proxy scheme + tag manipulation helpers."""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import re
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlparse, urlunparse

from .schemes import FRAGMENT_TAGGED, proxyScheme
from .uri import Create_ss_url_withPlugin, processShadowJson
from .utils import base64Decode, is_truthy, isBase64

__all__ = [
    "checkPatternsInList",
    "extractIPs",
    "parseAnytls",
    "parseContent",
    "parseHysteria",
    "parseHysteria2",
    "parseJuicity",
    "parseNaive",
    "parseShadowTls",
    "parseSsh",
    "parseTrojan",
    "parseTuic",
    "parseVless",
    "parseWireguard",
    "parse_ss",
    "parse_ss_withPlugin",
    "parse_ssr",
    "parse_userinfo",
    "tagChanger",
    "tagsChanger",
]

_KNOWN_SS_PLUGINS = frozenset(
    {
        "obfs-local",
        "simple-obfs",
        "v2ray-plugin",
        "xray-plugin",
        "shadow-tls",
        "kcptun-client",
    }
)

_RE_SS_USERINFO = re.compile(r"^(.+?):(.+)@(.+):(\d+)")
_RE_USER_HOSTPORT = re.compile(r"^(.+)@(.+):(\d+)$")

_HOSTNAME_ONLY_SCHEMES = FRAGMENT_TAGGED | {"naive", "naive+https"}


def _hostport(loaded):
    """Extract `(hostname, port)` from a urllib `SplitResult` / `ParseResult`."""
    host = loaded.hostname or ""
    if not loaded.port:
        raise ValueError(f"missing port in URL {loaded.geturl()!r}")
    return host, int(loaded.port)


def _match_userpw(text, label):
    m = _RE_SS_USERINFO.search(text)
    if not m:
        raise ValueError(f"{label} did not match method:pw@host:port: {text!r}")
    return m.groups()


def parse_ss(ss_url):
    # SS-URI = "ss://" userinfo "@" hostname ":" port ["/"] ["?"plugin] ["#" tag]
    mainPart = ss_url.split("#", 1)[0][5:]

    plugin = ""
    if "?" in mainPart:
        head, _, tail = mainPart.partition("?")
        plugin = tail
        mainPart = head.rstrip("/")

    if isBase64(mainPart):
        mainPart = base64Decode(mainPart)
    else:
        decoded = mainPart[: mainPart.find("@")]
        mainPart = mainPart.replace(decoded, base64Decode(decoded), 1)

    method, password, server, server_port = _match_userpw(unquote(mainPart), "ss URL")
    logging.debug(f"{server}:{server_port} {method} {password} {plugin}")
    return server, server_port, method, password


def parse_ss_withPlugin(ss_url):
    # SIP002: https://shadowsocks.org/guide/sip002.html
    body, _, tag = ss_url[5:].partition("#")

    plugin, plugin_opts = "", ""
    if "?" in body:
        body, query = body.split("?", 1)
        with contextlib.suppress(ValueError, KeyError, IndexError):
            plugin, plugin_opts = parse_qs(query)["plugin"][0].split(";", 1)

    if plugin and plugin not in _KNOWN_SS_PLUGINS:
        logging.warning(f"unknown SS plugin: {plugin}")

    body = body.rstrip("/")

    if isBase64(body):
        body = base64Decode(body)
    else:
        userinfo = unquote(body[: body.find("@")])
        if ":" not in userinfo:
            userinfo = base64Decode(userinfo)
        body = userinfo + body[body.find("@") :]

    method, password, server, server_port = _match_userpw(unquote(body), "ss URL")
    return server, server_port, method, password, plugin, plugin_opts, unquote(tag)


def parse_ssr(ssr_url):
    address, port, protocol, method, obfs, etc = base64Decode(ssr_url[6:]).split(":")
    password, _, pluginArgs = etc.partition("/?")
    args = parse_qs(pluginArgs)

    def _decode(key):
        return base64Decode(args.get(key, [""])[0])

    return {
        "address": address,
        "port": port,
        "protocol": protocol,
        "method": method,
        "obfs": obfs,
        "password": base64Decode(password),
        "obfsparam": _decode("obfsparam"),
        "protoparam": _decode("protoparam"),
        "remarks": _decode("remarks"),
        "group": _decode("group"),
    }


def parseVless(loaded):
    m = _RE_USER_HOSTPORT.search(loaded.netloc)
    if not m:
        raise ValueError(f"vless URL netloc did not match user@host:port: {loaded.netloc!r}")
    uid, address, port = m.groups()
    if address.startswith("["):
        address = address[1:-1]

    queryDict = dict(parse_qsl(loaded.query))

    def _none_or(x):
        return "" if x == "none" else x

    queryDict["protocol"] = loaded.scheme
    queryDict["add"] = address
    queryDict["port"] = port
    queryDict["id"] = uid
    queryDict["net"] = _none_or(queryDict.pop("type", ""))
    if queryDict["net"] == "grpc":
        queryDict["path"] = _none_or(queryDict.pop("serviceName", ""))
    queryDict["tls"] = _none_or(queryDict.pop("security", ""))
    queryDict["encryption"] = "none"

    return queryDict


def parseTrojan(loaded):
    queryDict = dict(parse_qsl(loaded.query))
    m = _RE_USER_HOSTPORT.search(loaded.netloc)
    if not m:
        raise ValueError(f"trojan netloc did not match pw@host:port: {loaded.netloc!r}")
    queryDict["password"], queryDict["address"], queryDict["port"] = m.groups()
    if "peer" in queryDict and "sni" not in queryDict:
        queryDict["sni"] = queryDict["peer"]
    if (insecure := queryDict.get("allowInsecure") or queryDict.get("allowinsecure")) is not None:
        queryDict["allowInsecure"] = "1" if is_truthy(insecure) else "0"
    return queryDict


def parse_userinfo(loaded, *, user_key=None, password_key="password"):
    """Parse `<scheme>://[user[:pwd]]@host:port?...` URLs into a flat dict."""
    host, port = _hostport(loaded)
    query = dict(parse_qsl(loaded.query.replace("&amp%3B", "&"), keep_blank_values=True))
    query["address"] = host
    query["port"] = port
    if user_key is not None:
        query[user_key] = unquote(loaded.username or "")
        query[password_key] = unquote(loaded.password or "")
    else:
        query[password_key] = unquote(loaded.username or "")
    return query


# Userinfo-only schemes share the same shape — alias.
parseHysteria2 = parse_userinfo
parseAnytls = parse_userinfo
parseShadowTls = parse_userinfo


def parseHysteria(loaded):
    host, port = _hostport(loaded)
    query = dict(parse_qsl(loaded.query, keep_blank_values=True))
    query["address"] = host
    query["port"] = port
    return query


def parseTuic(loaded):
    return parse_userinfo(loaded, user_key="uuid")


parseJuicity = parseTuic


def parseNaive(loaded):
    return parse_userinfo(loaded, user_key="username")


def parseSsh(loaded):
    return parse_userinfo(loaded, user_key="user")


def parseWireguard(loaded):
    host, port = _hostport(loaded)
    query = dict(parse_qsl(loaded.query, keep_blank_values=True))
    query.update(
        {
            "address": host,
            "port": port,
            "private_key": unquote(loaded.username or ""),
        }
    )
    return query


_IP_EXTRACTORS = {
    "ss": lambda proxy, _l: parse_ss_withPlugin(proxy)[0],
    "ssr": lambda proxy, _l: parse_ssr(proxy)["address"],
    "vmess": lambda proxy, _l: json.loads(base64Decode(proxy[8:]))["add"],
    "vless": lambda _p, loaded: parseVless(loaded)["add"],
    "trojan": lambda _p, loaded: parseTrojan(loaded)["address"],
}


def extractIPs(proxy):
    try:
        loaded = urlparse(proxy)
        if extractor := _IP_EXTRACTORS.get(loaded.scheme):
            return extractor(proxy, loaded)
        if loaded.scheme in _HOSTNAME_ONLY_SCHEMES:
            return loaded.hostname
        logging.error(f"Invalid proxy: {proxy}")
    except Exception as err:
        logging.error(f"Invalid proxy: {proxy} ({err})")
    return None


def checkPatternsInList(lines, patterns=proxyScheme):
    """Every proxy URL in *lines*, in order. A scheme must start a token, so
    `href="vmess://..."` in markup is not mistaken for a bare proxy."""
    prefixes = tuple(patterns)
    return [token for line in lines for token in line.split() if token.startswith(prefixes)]


def parseContent(content, patterns=proxyScheme):
    """Extract proxy URLs from a subscription body: a JSON array of shadowsocks
    servers, plain proxy URLs, or base64 (a blob per line, or one wrapped blob)."""
    content = content.replace("﻿", "").strip()  # BOMs also show up mid-body
    if not content:
        return []

    with contextlib.suppress(KeyError, TypeError, ValueError):
        if isinstance(json.loads(content), list):
            return processShadowJson(content)

    lines = content.splitlines()
    # Scanning prefixes first skips base64 work on every plain line.
    if found := checkPatternsInList(lines, patterns):
        return found

    # A body holding one blob per line only decodes line by line; a single blob
    # wrapped across lines only decodes rejoined. Keep whichever recovered more.
    decoded = []
    for line in lines:
        with contextlib.suppress(ValueError):
            decoded.extend(base64Decode(line).splitlines())
    joined = []
    with contextlib.suppress(ValueError):
        joined = base64Decode("".join(lines)).splitlines()
    return max(
        checkPatternsInList(decoded, patterns),
        checkPatternsInList(joined, patterns),
        key=len,
    )


def tagChanger(url, tag="4MahsaAmini"):
    loaded = urlparse(url)
    if loaded.scheme == "ss":
        return Create_ss_url_withPlugin(*parse_ss_withPlugin(url)[:6], tag)

    if loaded.scheme == "ssr":
        url = f"ssr://{base64Decode(url[6:])}"
        url_parts = list(urlparse(url))
        query = dict(parse_qsl(url_parts[4]))
        query["remarks"] = base64.urlsafe_b64encode(tag.encode())
        url_parts[4] = urlencode(dict(sorted(query.items())))
        return f"ssr://{base64.urlsafe_b64encode(urlunparse(url_parts)[6:].encode()).decode()}"

    if loaded.scheme == "vmess":
        if not isBase64(url[8:]):
            raise ValueError(f"vmess payload is not base64: {url[:32]}...")
        jsonLoad = json.loads(base64Decode(url[8:]))
        jsonLoad["ps"] = tag
        return f"vmess://{base64.b64encode(json.dumps(dict(sorted(jsonLoad.items()))).encode()).decode()}"

    if loaded.scheme in FRAGMENT_TAGGED:
        return loaded._replace(fragment=tag).geturl()

    return url  # scheme has no tag slot (naive)


def tagsChanger(urls, tag="4MahsaAmini", withCnt=False):
    lines = []
    for i, url in enumerate(urls):
        try:
            lines.append(tagChanger(url, f"{tag}-{i}" if withCnt else tag))
        except Exception as e:
            logging.debug("tagsChanger: failed for url=%r: %s", url, e)
    return lines
