"""xray-core / v2ray-core outbound config builders.

Schema reference: https://xtls.github.io/en/config/
"""

from __future__ import annotations

import json
import logging
from importlib.resources import files as _resource_files
from pathlib import Path
from urllib.parse import urlparse

from .parsers import (
    parse_ss_withPlugin,
    parse_ssr,
    parseTrojan,
    parseVless,
)
from .utils import (
    base64Decode,
    generate_uuid,
    is_truthy,
    is_valid_uuid,
    isBase64,
    mergeMultiDicts,
    normalize_network,
    split_csv,
)

__all__ = [
    "CLASH_SAMPLE_PATH",
    "SCHEMES",
    "createBatchConfig",
    "createConfig",
    "createShadowConfig",
    "createSsrConfig",
    "createTrojanConfig",
    "createVmessConfig",
    "dnsServers",
    "inbounds",
    "ssOut",
    "ssrOut",
    "trojanOut",
    "vmessOut",
    "writeConfig",
]

SCHEMES = frozenset({"vmess", "vless", "trojan", "ss", "ssr"})

CLASH_SAMPLE_PATH = str(_resource_files("proxyUtil") / "data" / "Clash-Template.yaml")

dnsServers = {"dns": {"servers": ["1.1.1.1", "8.8.8.8", "8.8.4.4", "localhost"]}}

inbounds = {
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": 1080,
            "protocol": "socks",
            "tag": "socksinbound",
            "settings": {"auth": "noauth", "udp": True, "ip": "0.0.0.0"},
        }
    ]
}

ssOut = {
    "outbounds": [
        {
            "protocol": "shadowsocks",
            "settings": {
                "plugin": "",
                "pluginOpts": "",
                "servers": [
                    {
                        "address": "serveraddr.com",
                        "method": "aes-128-gcm",
                        "password": "sspasswd",
                        "port": 1024,
                    }
                ],
            },
        }
    ]
}

ssrOut = {
    "outbounds": [
        {
            "protocol": "shadowsocks",
            "settings": {
                "plugin": "shadowsocksr",
                "pluginArgs": [],
                "servers": [
                    {
                        "address": "serveraddr.com",
                        "method": "aes-256-cfb",
                        "password": "sspasswd",
                        "port": 1024,
                    }
                ],
            },
        }
    ]
}

vmessOut = {
    "outbounds": [
        {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "serveraddr.com",
                        "port": 16823,
                        "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
                    }
                ]
            },
            "streamSettings": {
                "tlsSettings": {"disableSystemRoot": False},
                "xtlsSettings": {"disableSystemRoot": False},
            },
            "mux": {"enabled": False, "concurrency": -1},
        }
    ]
}

trojanOut = {
    "outbounds": [
        {
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": "serveraddr.com", "port": 1234, "password": "myP@5s"}],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": ""},
            },
        }
    ]
}

_SS_2022_PREFIX = "2022-"
_VALID_FLOWS = {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}


_SS_TPL = json.dumps(mergeMultiDicts(dnsServers, inbounds, ssOut))
_SSR_TPL = json.dumps(mergeMultiDicts(dnsServers, inbounds, ssrOut))
_VMESS_TPL = json.dumps(mergeMultiDicts(dnsServers, inbounds, vmessOut))
_TROJAN_TPL = json.dumps(mergeMultiDicts(dnsServers, inbounds, trojanOut))


def _build_tcp(jsonLoad):
    header_type = jsonLoad.get("headerType", "none")
    if header_type and header_type != "none":
        return {"network": "tcp", "tcpSettings": {"header": {"type": header_type}}}
    return {"network": "tcp"}


def _build_ws(jsonLoad):
    path = jsonLoad.get("path", "/")
    if jsonLoad.get("ed"):
        path = f"{path}{'&' if '?' in path else '?'}ed={jsonLoad['ed']}"
    ws = {"path": path}
    if "host" in jsonLoad:
        ws["headers"] = {"Host": jsonLoad["host"]}
    return {"network": "ws", "wsSettings": ws}


def _build_http(jsonLoad):
    http = {"path": jsonLoad.get("path", "/")}
    if "host" in jsonLoad:
        http["host"] = split_csv(jsonLoad["host"])
    if "method" in jsonLoad:
        http["method"] = jsonLoad["method"]
    return {"network": "http", "httpSettings": http}


def _build_grpc(jsonLoad):
    service = jsonLoad.get("serviceName") or jsonLoad.get("path", "")
    grpc = {"serviceName": service}
    mode = jsonLoad.get("mode")
    if mode:
        grpc["multiMode"] = mode == "multi"
    if "authority" in jsonLoad:
        grpc["authority"] = jsonLoad["authority"]
    return {"network": "grpc", "grpcSettings": grpc}


def _build_kcp(jsonLoad):
    kcp = {}
    if "seed" in jsonLoad:
        kcp["seed"] = jsonLoad["seed"]
    header_type = jsonLoad.get("headerType")
    if header_type:
        kcp["header"] = {"type": header_type}
    return {"network": "kcp", "kcpSettings": kcp}


def _build_quic(jsonLoad):
    quic = {
        "security": jsonLoad.get("quicSecurity", "none"),
        "key": jsonLoad.get("key", ""),
        "header": {"type": jsonLoad.get("headerType", "none")},
    }
    return {"network": "quic", "quicSettings": quic}


def _build_httpupgrade(jsonLoad):
    hu = {"path": jsonLoad.get("path", "/")}
    if "host" in jsonLoad:
        hu["host"] = jsonLoad["host"]
    return {"network": "httpupgrade", "httpupgradeSettings": hu}


def _build_xhttp(jsonLoad):
    xh = {"path": jsonLoad.get("path", "/")}
    if "host" in jsonLoad:
        xh["host"] = jsonLoad["host"]
    if "mode" in jsonLoad:
        xh["mode"] = jsonLoad["mode"]
    if "extra" in jsonLoad:
        try:
            xh["extra"] = json.loads(jsonLoad["extra"])
        except (ValueError, TypeError):
            xh["extra"] = jsonLoad["extra"]
    return {"network": "xhttp", "xhttpSettings": xh}


_TRANSPORT_BUILDERS = {
    "tcp": _build_tcp,
    "raw": _build_tcp,
    "ws": _build_ws,
    "h2": _build_http,
    "http": _build_http,
    "grpc": _build_grpc,
    "kcp": _build_kcp,
    "quic": _build_quic,
    "httpupgrade": _build_httpupgrade,
    "splithttp": _build_xhttp,
    "xhttp": _build_xhttp,
}


def _apply_tls_settings(stream, jsonLoad):
    tls_settings = stream.setdefault("tlsSettings", {})
    if "sni" in jsonLoad:
        tls_settings["serverName"] = jsonLoad["sni"]
    if "fp" in jsonLoad:
        tls_settings["fingerprint"] = jsonLoad["fp"]
    if "alpn" in jsonLoad:
        tls_settings["alpn"] = split_csv(jsonLoad["alpn"])
    if jsonLoad.get("ech_config") or jsonLoad.get("enableECH"):
        ech = {"enabled": True}
        if jsonLoad.get("ech_config"):
            ech["config"] = jsonLoad["ech_config"]
        tls_settings["echSettings"] = ech


def _apply_reality_settings(stream, jsonLoad):
    reality = {}
    for url_key, json_key in (
        ("sni", "serverName"),
        ("fp", "fingerprint"),
        ("pbk", "publicKey"),
        ("sid", "shortId"),
        ("spx", "spiderX"),
    ):
        if url_key in jsonLoad:
            reality[json_key] = jsonLoad[url_key]
    if "alpn" in jsonLoad:
        reality["alpn"] = split_csv(jsonLoad["alpn"])
    stream["realitySettings"] = reality


def createShadowConfig(ss_url, port=1080):
    config = json.loads(_SS_TPL)
    config["inbounds"][0]["port"] = port

    server, server_port, method, password, plugin, plugin_opts, _ = parse_ss_withPlugin(ss_url)
    settings = config["outbounds"][0]["settings"]
    settings["plugin"] = plugin
    settings["pluginOpts"] = plugin_opts
    server_cfg = settings["servers"][0]
    server_cfg["address"] = server
    server_cfg["port"] = int(server_port)
    server_cfg["method"] = method
    server_cfg["password"] = password

    if method.startswith(_SS_2022_PREFIX):
        server_cfg["uot"] = True
        server_cfg["UoTVersion"] = 2

    return config


def createSsrConfig(ssr_url, localPort=1080):
    config = json.loads(_SSR_TPL)
    parsed = parse_ssr(ssr_url)
    config["inbounds"][0]["port"] = localPort
    server_cfg = config["outbounds"][0]["settings"]["servers"][0]
    server_cfg["address"] = parsed["address"]
    server_cfg["port"] = int(parsed["port"])
    server_cfg["method"] = parsed["method"]
    server_cfg["password"] = parsed["password"]
    pluginArgs = config["outbounds"][0]["settings"]["pluginArgs"]
    pluginArgs.append(f"--obfs={parsed['obfs']}")
    pluginArgs.append(f"--obfs-param={parsed['obfsparam']}")
    pluginArgs.append(f"--protocol={parsed['protocol']}")
    pluginArgs.append(f"--protocol-param={parsed['protoparam']}")
    return config


def createVmessConfig(jsonLoad, port=1080):
    config = json.loads(_VMESS_TPL)
    config["inbounds"][0]["port"] = port

    outbound = config["outbounds"][0]
    outbound["protocol"] = jsonLoad.get("protocol", "vmess")
    vnext = outbound["settings"]["vnext"][0]
    vnext["address"] = jsonLoad["add"]

    if not jsonLoad.get("port"):
        raise ValueError("missing port in proxy URL")
    vnext["port"] = int(jsonLoad["port"])

    user = vnext["users"][0]
    user["id"] = jsonLoad["id"] if is_valid_uuid(jsonLoad["id"]) else generate_uuid(jsonLoad["id"])

    if jsonLoad.get("aid"):
        try:
            user["alterId"] = int(jsonLoad["aid"])
        except (ValueError, TypeError):
            logging.error(f"aid: {jsonLoad['aid']} is not int")

    if "encryption" in jsonLoad:
        user["encryption"] = jsonLoad["encryption"]

    flow = jsonLoad.get("flow")
    if flow:
        if flow in _VALID_FLOWS:
            user["flow"] = flow
        else:
            logging.warning(f"dropping unsupported flow={flow}")

    sec = jsonLoad.get("scy") or jsonLoad.get("security") or "auto"
    if sec != "auto":
        user["security"] = sec

    net = normalize_network(jsonLoad.get("net"))
    builder = _TRANSPORT_BUILDERS.get(net)
    if builder is None:
        logging.warning(f"unsupported transport: {net!r}")
    else:
        outbound["streamSettings"].update(builder(jsonLoad))

    if tls := jsonLoad.get("tls"):
        outbound["streamSettings"]["security"] = tls
        if tls == "reality":
            _apply_reality_settings(outbound["streamSettings"], jsonLoad)
        else:
            _apply_tls_settings(outbound["streamSettings"], jsonLoad)
    if is_truthy(jsonLoad.get("skip-cert-verify")) or is_truthy(jsonLoad.get("allowInsecure")):
        outbound["streamSettings"].setdefault("tlsSettings", {})["allowInsecure"] = True

    return config


def createTrojanConfig(loaded, localPort=1080):
    config = json.loads(_TROJAN_TPL)
    parsed = parseTrojan(loaded)

    config["inbounds"][0]["port"] = localPort
    server_cfg = config["outbounds"][0]["settings"]["servers"][0]
    server_cfg["address"] = parsed["address"]
    server_cfg["port"] = int(parsed["port"])
    server_cfg["password"] = parsed["password"]

    stream = config["outbounds"][0]["streamSettings"]
    net = normalize_network(parsed.get("type"))
    match net:
        case "ws":
            stream["network"] = "ws"
            ws = {"path": parsed.get("path", "/")}
            if "host" in parsed:
                ws["headers"] = {"Host": parsed["host"]}
            stream["wsSettings"] = ws
        case "grpc":
            stream["network"] = "grpc"
            stream["grpcSettings"] = {
                "serviceName": parsed.get("serviceName") or parsed.get("path", "")
            }
        case "h2" | "http":
            stream["network"] = "http"
            http = {"path": parsed.get("path", "/")}
            if "host" in parsed:
                http["host"] = [parsed["host"]]
            stream["httpSettings"] = http
        case "tcp":
            pass
        case _:
            stream["network"] = net

    if "security" in parsed:
        stream["security"] = parsed["security"]

    tls_settings = stream.setdefault("tlsSettings", {})
    if "sni" in parsed:
        tls_settings["serverName"] = parsed["sni"]
    if parsed.get("allowInsecure") == "1":
        tls_settings["allowInsecure"] = True
    if "fp" in parsed:
        tls_settings["fingerprint"] = parsed["fp"]
    if "alpn" in parsed:
        tls_settings["alpn"] = split_csv(parsed["alpn"])

    return config


def createConfig(url: str, localPort: int, *, listen: str = "0.0.0.0"):
    """Build an xray config dict for *url*. Returns None if unsupported.

    *listen* is the SOCKS inbound's bind address. The default keeps the historic
    all-interfaces bind for client use; throwaway checkers should pass ``127.0.0.1``.
    """
    config = _create_config(url, localPort)
    if config is not None:
        inbound = config["inbounds"][0]
        inbound["listen"] = listen
        inbound["settings"]["ip"] = listen
    return config


def _create_config(url: str, localPort: int):
    loaded = urlparse(url)
    scheme = loaded.scheme
    if scheme not in SCHEMES:
        return None
    try:
        match scheme:
            case "ss":
                return createShadowConfig(url, port=localPort)
            case "ssr":
                return createSsrConfig(url, localPort=localPort)
            case "vmess":
                if not isBase64(url[8:]):
                    logging.debug("Not Implemented this type of vmess url")
                    return None
                payload = json.loads(base64Decode(url[8:]))
                payload["protocol"] = "vmess"
                return createVmessConfig(payload, port=localPort)
            case "vless":
                return createVmessConfig(parseVless(loaded), port=localPort)
            case "trojan":
                return createTrojanConfig(loaded, localPort=localPort)
    except Exception as err:
        logging.error(f"skip {url} : {err}")
        return None
    return None


def writeConfig(url: str, localPort: int, path: str, *, listen: str = "0.0.0.0") -> str | None:
    cfg = createConfig(url, localPort, listen=listen)
    if cfg is None:
        return None
    out = Path(path) / f"xray_{localPort}.json"
    with out.open("w") as f:
        json.dump(cfg, f)
    logging.debug(f"xray config {out} created")
    return str(out)


def createBatchConfig(items, *, listen: str = "127.0.0.1"):
    """One xray config serving many `(url, port)` pairs: a SOCKS inbound per pair routed
    to its own outbound. Returns `(config, built)` where *built* lists the indices of
    *items* that produced an outbound (the rest are unsupported or malformed)."""
    config: dict = {
        "log": {"loglevel": "none"},
        "dns": dnsServers["dns"],
        "inbounds": [],
        "outbounds": [],
        "routing": {"rules": []},
    }
    built = []
    for index, (url, port) in enumerate(items):
        single = createConfig(url, port, listen=listen)
        if single is None:
            continue
        n = len(built)
        inbound, outbound = single["inbounds"][0], single["outbounds"][0]
        inbound["tag"], outbound["tag"] = f"in{n}", f"out{n}"
        config["inbounds"].append(inbound)
        config["outbounds"].append(outbound)
        config["routing"]["rules"].append(
            {"type": "field", "inboundTag": [f"in{n}"], "outboundTag": f"out{n}"}
        )
        built.append(index)
    return config, built
