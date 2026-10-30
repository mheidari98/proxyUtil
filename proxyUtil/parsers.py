"""URL parsers for every supported proxy scheme + tag manipulation helpers."""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import json
import logging
import re
from collections import Counter
from functools import lru_cache
from typing import NamedTuple
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlencode, urlparse, urlunparse

from .schemes import FRAGMENT_TAGGED, proxyScheme
from .uri import Create_ss_url_withPlugin, processShadowJson, quote_fragment
from .utils import base64Decode, ip_literal, is_truthy, isBase64, normalize_network

__all__ = [
    "checkPatternsInList",
    "dedupe_proxies",
    "extractIPs",
    "invalid_reason",
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
    "proxy_identity",
    "proxy_name",
    "reject_invalid",
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
_RE_BASE64 = re.compile(r"[A-Za-z0-9+/_-]+=*")

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
        return loaded._replace(fragment=quote_fragment(tag)).geturl()

    return url  # scheme has no tag slot (naive)


def tagsChanger(urls, tag="4MahsaAmini", withCnt=False):
    lines = []
    for i, url in enumerate(urls):
        try:
            lines.append(tagChanger(url, f"{tag}-{i}" if withCnt else tag))
        except Exception as e:
            logging.debug("tagsChanger: failed for url=%r: %s", url, e)
    return lines


# ---------------------------------------------------------------------------
# Normalized identity + structural validation
# ---------------------------------------------------------------------------

# Bump the tag whenever the normalization changes, so stored journals/history
# keyed by an older identity can never silently merge with (or split from) new keys.
_IDENTITY_TAG = "id1:"

_SCHEME_ALIASES = {"hy2": "hysteria2", "socks5h": "socks5", "socks": "socks5"}
_DEFAULT_PORTS = {"hysteria2": "443", "ssh": "22"}
_HOP_SCHEMES = frozenset({"hysteria", "hysteria2"})
# Schemes that always run over TLS: an explicit ``security=tls`` adds nothing.
_TLS_ONLY_SCHEMES = frozenset({"trojan", "hysteria", "hysteria2", "tuic", "juicity", "anytls"})
_V2RAY_SCHEMES = frozenset({"vmess", "vless", "trojan"})
_UUID_SCHEMES = frozenset({"vmess", "vless", "tuic", "juicity"})
_PASSWORD_SCHEMES = frozenset({"trojan", "ss", "hysteria2", "anytls"})

_PARAM_ALIASES = {
    "peer": "sni",
    "servername": "sni",
    "auth_str": "auth",
    "up": "upmbps",
    "down": "downmbps",
    "congestion-control": "congestion_control",
    "congestion_controller": "congestion_control",
    "packet-encoding": "packetencoding",
    "obfs_password": "obfs-password",
}
# Not part of the identity: display names / bookkeeping junk, and client-side knobs
# (fingerprint, ALPN, cert checking) that do not change which server is reached.
_DROP_PARAMS = frozenset(
    {
        *("ps", "v", "name", "remark", "remarks", "note", "telegram", "_t"),
        *("test_name", "survived_passes", "batch", "nation", "serverdescription"),
        *("fp", "alpn", "spx"),
        *("insecure", "insecur", "allowinsecure", "allow_insecure", "allowins"),
        "skip-cert-verify",
    }
)
_BOOL_PARAMS = frozenset(
    {"udp", "fastopen", "tfo", "mux", "reduce_rtt", "zero_rtt_handshake", "disable_sni"}
)
_LOWER_VALUE_PARAMS = frozenset(
    {
        *("type", "security", "headertype", "flow", "mode", "obfs"),
        *("sni", "host", "authority", "congestion_control", "udp_relay_mode", "packetencoding"),
    }
)
_DEFAULT_VALUES = {
    "type": frozenset({"tcp", "raw", "none"}),
    "security": frozenset({"none"}),
    "encryption": frozenset({"none"}),
    "headertype": frozenset({"none", "---", "auto", "null"}),
    "scy": frozenset({"auto", "null"}),
    "aid": frozenset({"0"}),
    "path": frozenset({"/"}),
}
_FALSY = frozenset({"0", "false", "no", "off"})
_SS_PLUGIN_ALIASES = {"simple-obfs": "obfs-local"}

_ZERO_UUID_CHARS = frozenset("0-")
_BAD_HOSTS = frozenset({"localhost", "0.0.0.0", "::", "example.com", "example.net", "example.org"})
_BAD_HOST_SUFFIXES = (
    ".local",
    ".invalid",
    ".test",
    ".example",
    ".localhost",
    *(f".{h}" for h in ("example.com", "example.net", "example.org")),
)


class _BadBase64(ValueError):
    """A vmess payload that does not decode as base64."""


class _Parts(NamedTuple):
    scheme: str
    cred: str
    host: str
    port: str
    path: str
    params: dict[str, str]


def _norm_host(host):
    host = unquote(host).strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return str(ip) if (ip := ip_literal(host)) else host


def _split_hostport(hostport):
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        return host, rest[1:] if rest.startswith(":") else ""
    if hostport.count(":") > 1:  # bare IPv6, with or without a trailing :port
        if ip := ip_literal(hostport):
            return str(ip), ""
        host, _, port = hostport.rpartition(":")
        return host, port
    host, _, port = hostport.partition(":")
    return host, port


def _hop_ranges(items):
    """Canonical port-hopping list: ``a-b`` ranges as ints, deduped, sorted by start."""
    out = set()
    for item in items:
        lo, sep, hi = item.strip().replace(":", "-").partition("-")
        if not lo.strip().isdigit() or (sep and not hi.strip().isdigit()):
            raise ValueError(f"bad port range {item!r}")
        lo = int(lo)
        out.add((lo, int(hi) if sep else lo))
    return [f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in sorted(out)]


def _norm_port(scheme, spec, params):
    spec = spec.strip()
    if scheme in _HOP_SCHEMES and ("," in spec or "-" in spec):
        entries = [p for p in spec.split(",") if p.strip()]
        spec = entries[0].strip() if entries and entries[0].strip().isdigit() else ""
        hops = entries[1:] if spec else entries
        if hops:
            params["mport"] = ",".join(filter(None, [params.get("mport", ""), *hops]))
    if not spec:
        spec = _DEFAULT_PORTS.get(scheme, "")
    port = str(int(spec)) if spec.isdigit() else spec
    if mport := params.pop("mport", ""):
        hops = [r for r in _hop_ranges(mport.split(",")) if r != port]
        if hops:
            params["mport"] = ",".join(hops)
    return port


def _canon_params(scheme, pairs, host):
    """Merge aliases, normalize spellings and drop default / identity-irrelevant params."""
    direct: dict[str, str] = {}
    aliased: dict[str, str] = {}
    for raw_key, raw_value in pairs:
        key = str(raw_key).strip().lower()
        while key.startswith("amp;"):
            key = key[4:]
        target = direct
        if key in _PARAM_ALIASES:
            key, target = _PARAM_ALIASES[key], aliased
        if key in _DROP_PARAMS or raw_value is None:
            continue
        value = str(raw_value).strip()
        if key in _BOOL_PARAMS or isinstance(raw_value, bool):
            if not value or value.lower() in _FALSY:
                continue
            value = "1" if is_truthy(value) else value
        if key in _LOWER_VALUE_PARAMS:
            value = value.lower()
        if key == "type":
            value = normalize_network(value)
        defaults = _DEFAULT_VALUES.get(key, ())
        if key == "security" and scheme in _TLS_ONLY_SCHEMES:
            defaults = ("tls",)  # absent means TLS here; an explicit "none" is not the default
        if value and value.lower() not in defaults:
            target.setdefault(key, value)
    params = {**aliased, **direct}  # an explicit `sni` beats `peer`, etc.
    if scheme in _V2RAY_SCHEMES and "type" not in params and "headertype" not in params:
        # Plain TCP sends no HTTP request: host/path are ignored (often channel spam).
        params.pop("host", None)
        params.pop("path", None)
    if params.get("sni") == host and ip_literal(host) is None:
        del params["sni"]  # a domain server's SNI defaults to the domain itself
    return params


def _parts_vmess(url):
    payload = url[8:].strip()
    if not _RE_BASE64.fullmatch(payload):  # b64decode would silently skip junk characters
        raise _BadBase64("vmess payload is not base64")
    try:
        text = base64Decode(payload)
    except ValueError as err:
        raise _BadBase64(str(err)) from err
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("vmess payload is not a JSON object")
    data = {str(k).strip().lower(): v for k, v in data.items()}
    if "scy" not in data and "security" in data:
        data["scy"] = data.pop("security")
    data.pop("security", None)
    host = _norm_host(str(data.pop("add", "") or ""))
    cred = str(data.pop("id", "") or "").strip().lower()
    port = str(data.pop("port", "") or "")
    # Rename to the vless spellings so one rule set covers both.
    tls = data.pop("tls", None)
    data["security"] = "tls" if tls is True or str(tls).strip().lower() == "true" else tls
    data["headertype"] = data.pop("type", None)
    data["type"] = data.pop("net", None)
    if (aid := str(data.get("aid", "")).strip()).isdigit():
        data["aid"] = str(int(aid))
    params = _canon_params("vmess", data.items(), host)
    return _Parts("vmess", cred, host, _norm_port("vmess", port, params), "", params)


def _parts_ss(url):
    body, _, query = url[5:].strip().partition("?")
    body = body.rstrip("/")
    if "@" not in body:  # legacy form: the whole method:password@host:port is base64
        body = base64Decode(unquote(body))
    userinfo, at, hostport = body.rpartition("@")
    if not at:
        raise ValueError("ss URL has no userinfo")
    userinfo = unquote(userinfo)
    if ":" not in userinfo:
        userinfo = base64Decode(userinfo)
    method, colon, password = userinfo.partition(":")
    if not colon:
        raise ValueError("ss userinfo is not method:password")
    host, port = _split_hostport(hostport.rstrip("/"))
    params = {"method": method.strip().lower()}
    if plugin := dict(parse_qsl(query)).get("plugin", "").strip():
        name, *opts = (p.strip() for p in plugin.split(";"))
        name = _SS_PLUGIN_ALIASES.get(name.lower(), name.lower())
        if name:
            params["plugin"] = ";".join([name, *sorted(o for o in opts if o)])
    return _Parts("ss", password, _norm_host(host), _norm_port("ss", port, params), "", params)


def _parts_ssr(url):
    d = parse_ssr(url)
    params = {k: str(d[k]) for k in ("protocol", "method", "obfs", "obfsparam", "protoparam")}
    params = {k: v for k, v in params.items() if v}
    host = _norm_host(d["address"])
    return _Parts("ssr", d["password"], host, _norm_port("ssr", d["port"], params), "", params)


def _parts_generic(scheme, rest):
    cut = min((i for i in (rest.find("/"), rest.find("?")) if i >= 0), default=len(rest))
    netloc, tail = rest[:cut], rest[cut:]
    path, _, query = tail.partition("?")
    userinfo, _, hostport = netloc.rpartition("@")
    host, port = _split_hostport(hostport)
    host = _norm_host(host)
    cred = unquote(userinfo).strip()
    if scheme in _UUID_SCHEMES:
        user, colon, pw = cred.partition(":")
        cred = user.strip().lower() + colon + pw
    query = query.replace("&amp%3B", "&").replace("&amp;", "&")
    params = _canon_params(scheme, parse_qsl(query, keep_blank_values=True), host)
    path = unquote(path)
    return _Parts(
        scheme, cred, host, _norm_port(scheme, port, params), "" if path == "/" else path, params
    )


def _proxy_parts(url):
    """Decompose *url* into its identity-relevant parts. Raises ValueError (or
    `_BadBase64`) when the URL cannot be understood."""
    url = url.strip().split("#", 1)[0]
    scheme, sep, rest = url.partition("://")
    if not sep or not scheme:
        raise ValueError("not a URL")
    scheme = scheme.strip().lower()
    scheme = _SCHEME_ALIASES.get(scheme, scheme)
    try:
        match scheme:
            case "vmess":
                return _parts_vmess(url)
            case "ss":
                return _parts_ss(url)
            case "ssr":
                return _parts_ssr(url)
            case _:
                return _parts_generic(scheme, rest)
    except (KeyError, IndexError, TypeError, AttributeError) as err:
        raise ValueError(str(err)) from err


@lru_cache(maxsize=1 << 17)  # the checker re-derives the same key for dedupe, resume and journal
def proxy_identity(url):
    """Key that is equal for configs reaching the same server the same way.

    Ignores the display name (fragment, vmess ``ps``) and spelling differences:
    scheme / parameter aliases (``hy2``, ``peer``), parameter order, percent-encoding,
    defaults spelled out or omitted, vmess JSON value types and base64 variants. Also
    ignores client-side knobs (``fp``, ``alpn``, ``insecure``): configs differing only
    there are tested once. Keys are tagged ``id1:``; URLs that cannot be parsed fall back
    to ``raw:`` + the URL without its fragment.
    """
    try:
        p = _proxy_parts(url)
    except ValueError:
        return "raw:" + url.strip().split("#", 1)[0]
    host = f"[{p.host}]" if ":" in p.host else p.host
    query = urlencode(sorted(p.params.items()))
    return f"{_IDENTITY_TAG}{p.scheme}://{quote(p.cred, safe='')}@{host}:{p.port}{p.path}?{query}"


def _host_reason(host):
    if not host or host in _BAD_HOSTS or host.endswith(_BAD_HOST_SUFFIXES):
        return "host"
    if (ip := ip_literal(host)) is None:
        return None if "." in host else "host"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "private-ip"
    return None


def invalid_reason(url):
    """Why *url* can never work, judged from its structure alone (no network), or None.

    Reasons: ``unparsable``, ``base64`` (vmess payload), ``port``, ``host``,
    ``private-ip`` and ``no-credential``. Ciphers / transports are left to the cores.
    """
    try:
        p = _proxy_parts(url)
    except _BadBase64:
        return "base64"
    except ValueError:
        return "unparsable"
    hop_only = p.port == "" and "mport" in p.params  # hysteria `host:20000-30000`
    if not hop_only and (not p.port.isdigit() or not 1 < int(p.port) <= 65535):
        return "port"
    if reason := _host_reason(p.host):
        return reason
    if p.scheme in _UUID_SCHEMES and set(p.cred.partition(":")[0]) <= _ZERO_UUID_CHARS:
        return "no-credential"
    if p.scheme in _PASSWORD_SCHEMES and not p.cred:
        return "no-credential"
    return None


def reject_invalid(urls):
    """Split *urls* into the structurally valid ones (in order) and a Counter of
    rejection reasons."""
    kept: list[str] = []
    reasons: Counter[str] = Counter()
    for url in urls:
        if reason := invalid_reason(url):
            reasons[reason] += 1
        else:
            kept.append(url)
    return kept, reasons


def dedupe_proxies(urls):
    """Drop proxies that differ only by name, keeping the first of each, in order."""
    seen: dict[str, str] = {}
    for url in urls:
        seen.setdefault(proxy_identity(url), url)
    return list(seen.values())


def proxy_name(url):
    """The display name stored in a proxy URL (fragment, or vmess ``ps``); "" if none."""
    try:
        match urlparse(url).scheme:
            case "vmess":
                return str(json.loads(base64Decode(url[8:].split("#", 1)[0])).get("ps", ""))
            case "ss":
                return parse_ss_withPlugin(url)[6] or ""
            case "ssr":
                return parse_ssr(url)["remarks"]
            case _:
                return unquote(urlparse(url).fragment)
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return ""
