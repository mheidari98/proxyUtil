"""URL parsers for every supported proxy scheme + tag manipulation helpers."""

from __future__ import annotations

import base64
import json
import logging
import re
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlparse, urlunparse

from .schemes import FRAGMENT_TAGGED, proxyScheme
from .uri import Create_ss_url_withPlugin, processShadowJson
from .utils import base64Decode, is_json, is_truthy, isBase64

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

_KNOWN_SS_PLUGINS = {
    "obfs-local",
    "simple-obfs",
    "v2ray-plugin",
    "xray-plugin",
    "shadow-tls",
    "kcptun-client",
}


def _hostport(loaded):
    """Extract `(hostname, port)` from a urllib `SplitResult` / `ParseResult`."""
    host = loaded.hostname or ""
    if not loaded.port:
        raise ValueError(f"missing port in URL {loaded.geturl()!r}")
    return host, int(loaded.port)


def parse_ss(ss_url):
    # SS-URI = "ss://" userinfo "@" hostname ":" port ["/"] ["?"plugin] ["#" tag]
    mainPart = ss_url.split("#")[0][5:]

    try:
        plugin = mainPart.split("?")[1]
        mainPart = mainPart[: re.search(r"/\?", mainPart).start()]
    except (IndexError, AttributeError):
        plugin = ""

    if isBase64(mainPart):
        mainPart = base64Decode(mainPart)
    else:
        decoded = mainPart[: mainPart.find("@")]
        mainPart = mainPart.replace(decoded, base64Decode(decoded), 1)

    method, password, server, server_port = re.search(
        r"^(.+?):(.+)@(.+):(\d+)", unquote(mainPart)
    ).groups()
    logging.debug(f"{server}:{server_port} {method} {password} {plugin}")
    return server, server_port, method, password


def parse_ss_withPlugin(ss_url):
    # SIP002: https://shadowsocks.org/guide/sip002.html
    mainPart, tag = ([*ss_url[5:].split("#", 1), ""])[:2]

    try:
        mainPart, query = mainPart.split("?")
        plugin, plugin_opts = parse_qs(query)["plugin"][0].split(";", 1)
    except (ValueError, KeyError, IndexError):
        plugin, plugin_opts = "", ""

    if plugin and plugin not in _KNOWN_SS_PLUGINS:
        logging.warning(f"unknown SS plugin: {plugin}")

    if mainPart[-1] == "/":
        mainPart = mainPart[:-1]

    if isBase64(mainPart):
        mainPart = base64Decode(mainPart)
    else:
        decoded = unquote(mainPart[: mainPart.find("@")])
        if ":" not in decoded:
            decoded = base64Decode(decoded)
        mainPart = decoded + mainPart[mainPart.find("@") :]

    method, password, server, server_port = re.search(
        r"^(.+?):(.+)@(.+):(\d+)", unquote(mainPart)
    ).groups()

    return server, server_port, method, password, plugin, plugin_opts, unquote(tag)


def parse_ssr(ssr_url):
    ssr_parsed = {}
    (
        ssr_parsed["address"],
        ssr_parsed["port"],
        ssr_parsed["protocol"],
        ssr_parsed["method"],
        ssr_parsed["obfs"],
        etc,
    ) = base64Decode(ssr_url[6:]).split(":")
    password, _sep, pluginArgs = etc.partition("/?")
    ssr_parsed["password"] = base64Decode(password)
    ssr_parsed["obfsparam"] = base64Decode(parse_qs(pluginArgs).get("obfsparam", [""])[0])
    ssr_parsed["protoparam"] = base64Decode(parse_qs(pluginArgs).get("protoparam", [""])[0])
    ssr_parsed["remarks"] = base64Decode(parse_qs(pluginArgs).get("remarks", [""])[0])
    ssr_parsed["group"] = base64Decode(parse_qs(pluginArgs).get("group", [""])[0])
    return ssr_parsed


def parseVless(loaded):
    uid, address, port = re.search(r"^(.+)@(.+):(\d+)$", loaded.netloc).groups()
    if address[0] == "[":
        address = address[1:-1]
    queryDict = dict(parse_qsl(loaded.query))

    def notNone(x):
        return x if x != "none" else ""

    queryDict["protocol"] = loaded.scheme
    queryDict["add"] = address
    queryDict["port"] = port
    queryDict["id"] = uid
    queryDict["net"] = notNone(queryDict.pop("type") if "type" in queryDict else "")
    if queryDict["net"] == "grpc":
        queryDict["path"] = notNone(
            queryDict.pop("serviceName") if "serviceName" in queryDict else ""
        )
    queryDict["tls"] = notNone(queryDict.pop("security") if "security" in queryDict else "")
    queryDict["encryption"] = "none"

    return queryDict


def parseTrojan(loaded):
    queryDict = dict(parse_qsl(loaded.query))
    res = re.search(r"^(.+)@(.+):(\d+)$", loaded.netloc)
    if not res:
        raise ValueError("Wrong Trojan URI")
    queryDict["password"], queryDict["address"], queryDict["port"] = res.groups()
    if "peer" in queryDict and "sni" not in queryDict:
        queryDict["sni"] = queryDict["peer"]
    insecure = queryDict.get("allowInsecure") or queryDict.get("allowinsecure")
    if insecure is not None:
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
    private = unquote(loaded.username or "")
    query = dict(parse_qsl(loaded.query, keep_blank_values=True))
    query.update({"address": host, "port": port, "private_key": private})
    return query


def extractIPs(proxy):
    try:
        loaded = urlparse(proxy)
        scheme = loaded.scheme
        if scheme == "ss":
            return parse_ss_withPlugin(proxy)[0]
        if scheme == "ssr":
            return parse_ssr(proxy)["address"]
        if scheme == "vmess":
            return json.loads(base64Decode(proxy[8:]))["add"]
        if scheme == "vless":
            return parseVless(loaded)["add"]
        if scheme == "trojan":
            return parseTrojan(loaded)["address"]
        if scheme in {
            "hysteria",
            "hysteria2",
            "hy2",
            "tuic",
            "anytls",
            "shadowtls",
            "ssh",
            "wireguard",
            "juicity",
            "naive",
            "naive+https",
        }:
            return loaded.hostname
        logging.error(f"Invalid proxy: {proxy}")
    except Exception as err:
        logging.error(f"Invalid proxy: {proxy} ({err})")
    return None


def checkPatternsInList(lines, patterns=proxyScheme):
    result = []
    for line in lines:
        for pattern in patterns:
            res = re.search(rf"(\S*\s+|^)({pattern}\S+)", line)
            if res:
                result.append(res.group(2))
                break
    return result


def parseContent(content, patterns=proxyScheme):
    if is_json(content):
        return processShadowJson(content)
    lines = []
    for line in content.splitlines():
        if isBase64(line):
            line = base64Decode(line)
        lines.extend(line.split())
    return checkPatternsInList(lines, patterns)


def tagChanger(url, tag="4MahsaAmini"):
    loaded = urlparse(url)
    if loaded.scheme == "ss":
        return Create_ss_url_withPlugin(*parse_ss_withPlugin(url)[:6], tag)

    if loaded.scheme == "ssr":
        url = f"ssr://{base64Decode(url[6:])}"
        params = {"remarks": base64.urlsafe_b64encode(tag.encode())}
        url_parts = list(urlparse(url))
        query = dict(parse_qsl(url_parts[4]))
        query.update(params)
        url_parts[4] = urlencode(dict(sorted(query.items())))
        return f"ssr://{base64.urlsafe_b64encode(urlunparse(url_parts)[6:].encode()).decode()}"

    if loaded.scheme == "vmess" and isBase64(url[8:]):
        jsonLoad = json.loads(base64Decode(url[8:]))
        jsonLoad["ps"] = tag
        return (
            "vmess://"
            + base64.b64encode(json.dumps(dict(sorted(jsonLoad.items()))).encode()).decode()
        )

    if loaded.scheme in FRAGMENT_TAGGED:
        return loaded._replace(fragment=tag).geturl()

    return url


def tagsChanger(urls, tag="4MahsaAmini", withCnt=False):
    lines = []
    newTAG = tag
    for i, url in enumerate(urls):
        try:
            if withCnt:
                newTAG = f"{tag}-{i}"
            lines.append(tagChanger(url, newTAG))
        except Exception as e:
            logging.debug("tagsChanger: failed for url=%r: %s", url, e)
    return lines
