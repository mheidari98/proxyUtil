"""sing-box outbound config builder.

Schema reference: https://sing-box.sagernet.org/configuration/outbound/

This is the unified core: it speaks every scheme proxyUtil supports, including
the schemes xray-core does not (hysteria, hysteria2, tuic, anytls, shadowtls,
naive, ssh, wireguard, juicity).

Notes / gotchas baked in:
- Reality requires `tls.enabled`, `tls.reality.enabled`, and `tls.utls.enabled`
  set together; helper `_reality_block` enforces this.
- xray-only `xhttp` / `splithttp` transports are downgraded to sing-box
  `httpupgrade` with a warning.
- juicity has no native sing-box outbound; emitted as tuic v5 with bbr+native.
- anytls requires sing-box >= 1.11; gated by ``MIN_SINGBOX_VERSION_ANYTLS``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import urlsplit

from .parsers import (
    parse_ss_withPlugin,
    parseAnytls,
    parseHysteria,
    parseHysteria2,
    parseJuicity,
    parseNaive,
    parseShadowTls,
    parseSsh,
    parseTrojan,
    parseTuic,
    parseVless,
    parseWireguard,
)
from .utils import (
    base64Decode,
    generate_uuid,
    is_truthy,
    is_valid_uuid,
    isBase64,
    normalize_network,
    split_csv,
)

__all__ = [
    "MIN_SINGBOX_VERSION_ANYTLS",
    "SCHEMES",
    "build_singbox_batch",
    "build_singbox_config",
    "writeConfig",
]

SCHEMES = frozenset(
    {
        "ss",
        "vmess",
        "vless",
        "trojan",
        "hysteria",
        "hysteria2",
        "hy2",
        "tuic",
        "anytls",
        "shadowtls",
        "naive",
        "naive+https",
        "ssh",
        "wireguard",
        "juicity",
    }
)

MIN_SINGBOX_VERSION_ANYTLS = "1.11.0"

_SINGBOX_BASE_TPL = json.dumps(
    {
        "log": {"level": "panic", "disabled": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": 1080,
                "sniff": False,
                "users": [],
            }
        ],
        "outbounds": [],
    }
)


def _tls_block(parsed: dict, *, default_alpn=None) -> dict:
    tls: dict = {"enabled": True}
    sni = parsed.get("sni") or parsed.get("peer")
    if sni:
        tls["server_name"] = sni
    if is_truthy(
        parsed.get("insecure") or parsed.get("allowInsecure") or parsed.get("allow_insecure")
    ):
        tls["insecure"] = True
    alpn = split_csv(parsed.get("alpn")) or list(default_alpn or [])
    if alpn:
        tls["alpn"] = alpn
    if parsed.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": parsed["fp"]}
    return tls


def _reality_block(parsed: dict) -> dict:
    tls: dict = {"enabled": True}
    if parsed.get("sni"):
        tls["server_name"] = parsed["sni"]
    tls["utls"] = {"enabled": True, "fingerprint": parsed.get("fp", "chrome")}
    reality: dict = {"enabled": True}
    if parsed.get("pbk"):
        reality["public_key"] = parsed["pbk"]
    if parsed.get("sid"):
        reality["short_id"] = parsed["sid"]
    tls["reality"] = reality
    return tls


def _transport_block(parsed: dict) -> dict | None:
    """Build sing-box `transport` from xray-style URL keys. None for tcp/none."""
    net = normalize_network(parsed.get("net") or parsed.get("type"))
    host = parsed.get("host")
    path = parsed.get("path", "/")

    def _httpupgrade():
        return {"type": "httpupgrade", "path": path, **({"host": host} if host else {})}

    match net:
        case "" | "tcp" | "raw" | "none":
            return None
        case "ws":
            block = {"type": "ws", "path": path}
            if host:
                block["headers"] = {"Host": host}
            if ed := parsed.get("ed"):
                block["max_early_data"] = int(ed)
                block["early_data_header_name"] = "Sec-WebSocket-Protocol"
            return block
        case "grpc":
            return {
                "type": "grpc",
                "service_name": parsed.get("serviceName") or parsed.get("path", ""),
            }
        case "h2" | "http":
            block = {"type": "http", "path": path}
            if host:
                block["host"] = split_csv(host)
            return block
        case "httpupgrade":
            return _httpupgrade()
        case "quic":
            return {"type": "quic"}
        case "xhttp" | "splithttp":
            target = parsed.get("add") or parsed.get("address")
            logging.warning(
                f"sing-box has no {net!r} transport; downgrading to httpupgrade for {target}"
            )
            return _httpupgrade()
        case _:
            logging.warning(f"unsupported sing-box transport {net!r}; emitting plain TCP")
            return None


def _outbound_hysteria2(parsed):
    out = {
        "type": "hysteria2",
        "tag": "out",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "password": parsed["password"],
        "tls": _tls_block(parsed, default_alpn=["h3"]),
    }
    if "obfs" in parsed:
        out["obfs"] = {"type": parsed["obfs"], "password": parsed.get("obfs-password", "")}
    if "up" in parsed:
        out["up_mbps"] = int(parsed["up"])
    if "down" in parsed:
        out["down_mbps"] = int(parsed["down"])
    return out


def _outbound_hysteria(parsed):
    out = {
        "type": "hysteria",
        "tag": "out",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "tls": _tls_block(parsed, default_alpn=["h3"]),
    }
    if "auth" in parsed:
        out["auth_str"] = parsed["auth"]
    if "upmbps" in parsed:
        out["up_mbps"] = int(parsed["upmbps"])
    if "downmbps" in parsed:
        out["down_mbps"] = int(parsed["downmbps"])
    if "obfs" in parsed:
        out["obfs"] = parsed["obfs"]
    return out


def _outbound_tuic(parsed):
    return {
        "type": "tuic",
        "tag": "out",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "uuid": parsed["uuid"],
        "password": parsed["password"],
        "congestion_control": parsed.get("congestion_control", "cubic"),
        "udp_relay_mode": parsed.get("udp_relay_mode", "native"),
        "zero_rtt_handshake": is_truthy(parsed.get("zero_rtt_handshake")),
        "tls": _tls_block(parsed, default_alpn=["h3"]),
    }


def _outbound_anytls(parsed):
    return {
        "type": "anytls",
        "tag": "out",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "password": parsed["password"],
        "tls": _tls_block(parsed),
    }


def _outbound_shadowtls(parsed):
    out = {
        "type": "shadowtls",
        "tag": "out",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "version": int(parsed.get("version", 3)),
        "password": parsed["password"],
        "tls": _tls_block(parsed),
    }
    return out


def _outbound_naive(parsed):
    return {
        "type": "naive",
        "tag": "out",
        "network": "tcp",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "username": parsed.get("username", ""),
        "password": parsed.get("password", ""),
        "tls": _tls_block(parsed),
    }


def _outbound_ssh(parsed):
    out = {
        "type": "ssh",
        "tag": "out",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "user": parsed.get("user", ""),
    }
    if parsed.get("password"):
        out["password"] = parsed["password"]
    return out


def _outbound_wireguard(parsed):
    return {
        "type": "wireguard",
        "tag": "out",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "private_key": parsed.get("private_key", ""),
        "peer_public_key": parsed.get("publickey", ""),
        "local_address": parsed.get("address_v4", "172.16.0.2/32").split(","),
    }


def _outbound_shadowsocks(ss_url):
    server, port, method, password, plugin, plugin_opts, _ = parse_ss_withPlugin(ss_url)
    out = {
        "type": "shadowsocks",
        "tag": "out",
        "server": server,
        "server_port": int(port),
        "method": method,
        "password": password,
    }
    if plugin:
        out["plugin"] = plugin
        out["plugin_opts"] = plugin_opts
    if method.startswith("2022-"):
        out["udp_over_tcp"] = {"enabled": True, "version": 2}
    return out


def _outbound_trojan(loaded):
    parsed = parseTrojan(loaded)
    out = {
        "type": "trojan",
        "tag": "out",
        "server": parsed["address"],
        "server_port": int(parsed["port"]),
        "password": parsed["password"],
        "tls": _tls_block(parsed),
    }
    transport = _transport_block(parsed)
    if transport:
        out["transport"] = transport
    return out


def _outbound_vmess(jsonLoad):
    out = {
        "type": "vmess",
        "tag": "out",
        "server": jsonLoad["add"],
        "server_port": int(jsonLoad["port"]),
        "uuid": (
            jsonLoad["id"] if is_valid_uuid(jsonLoad["id"]) else generate_uuid(jsonLoad["id"])
        ),
        "alter_id": int(jsonLoad.get("aid") or 0),
        "security": jsonLoad.get("scy") or jsonLoad.get("security") or "auto",
    }
    if jsonLoad.get("tls") == "reality":
        out["tls"] = _reality_block(jsonLoad)
    elif jsonLoad.get("tls"):
        out["tls"] = _tls_block(jsonLoad)
    transport = _transport_block(jsonLoad)
    if transport:
        out["transport"] = transport
    return out


def _outbound_vless(loaded):
    jsonLoad = parseVless(loaded)
    out = {
        "type": "vless",
        "tag": "out",
        "server": jsonLoad["add"],
        "server_port": int(jsonLoad["port"]),
        "uuid": (
            jsonLoad["id"] if is_valid_uuid(jsonLoad["id"]) else generate_uuid(jsonLoad["id"])
        ),
    }
    if jsonLoad.get("flow"):
        out["flow"] = jsonLoad["flow"]
    if jsonLoad.get("tls") == "reality":
        out["tls"] = _reality_block(jsonLoad)
    elif jsonLoad.get("tls"):
        out["tls"] = _tls_block(jsonLoad)
    transport = _transport_block(jsonLoad)
    if transport:
        out["transport"] = transport
    return out


def build_singbox_config(url, localPort, *, listen="127.0.0.1"):
    loaded = urlsplit(url)
    scheme = loaded.scheme
    if scheme not in SCHEMES:
        return None

    try:
        match scheme:
            case "hysteria2" | "hy2":
                outbound = _outbound_hysteria2(parseHysteria2(loaded))
            case "hysteria":
                outbound = _outbound_hysteria(parseHysteria(loaded))
            case "tuic":
                outbound = _outbound_tuic(parseTuic(loaded))
            case "juicity":
                outbound = _outbound_tuic(parseJuicity(loaded)) | {
                    "congestion_control": "bbr",
                    "udp_relay_mode": "native",
                }
            case "anytls":
                outbound = _outbound_anytls(parseAnytls(loaded))
            case "shadowtls":
                outbound = _outbound_shadowtls(parseShadowTls(loaded))
            case "naive" | "naive+https":
                outbound = _outbound_naive(parseNaive(loaded))
            case "ssh":
                outbound = _outbound_ssh(parseSsh(loaded))
            case "wireguard":
                outbound = _outbound_wireguard(parseWireguard(loaded))
            case "ss":
                outbound = _outbound_shadowsocks(url)
            case "trojan":
                outbound = _outbound_trojan(loaded)
            case "vless":
                outbound = _outbound_vless(loaded)
            case "vmess":
                payload = url[len("vmess://") :]
                if not isBase64(payload):
                    return None
                outbound = _outbound_vmess(json.loads(base64Decode(payload)))
            case _:
                return None
    except (AttributeError, KeyError, ValueError, TypeError) as err:
        logging.error(f"skip {url} : {err}")
        return None

    config = json.loads(_SINGBOX_BASE_TPL)
    config["inbounds"][0]["listen"] = listen
    config["inbounds"][0]["listen_port"] = localPort
    config["outbounds"].append(outbound)
    return config


def writeConfig(url, localPort, path, *, listen="127.0.0.1"):
    config = build_singbox_config(url, localPort, listen=listen)
    if config is None:
        return None
    out = Path(path) / f"singbox_{localPort}.json"
    with out.open("w") as f:
        json.dump(config, f)
    return str(out)


def build_singbox_batch(items, *, listen="127.0.0.1"):
    """One sing-box config serving many `(url, port)` pairs; see ``xray.createBatchConfig``."""
    config = json.loads(_SINGBOX_BASE_TPL)
    config["inbounds"], config["outbounds"] = [], []
    rules, built = [], []
    for index, (url, port) in enumerate(items):
        single = build_singbox_config(url, port, listen=listen)
        if single is None:
            continue
        n = len(built)
        inbound, outbound = single["inbounds"][0], single["outbounds"][0]
        inbound["tag"], outbound["tag"] = f"in{n}", f"out{n}"
        config["inbounds"].append(inbound)
        config["outbounds"].append(outbound)
        rules.append({"inbound": [f"in{n}"], "action": "route", "outbound": f"out{n}"})
        built.append(index)
    config["route"] = {"rules": rules}
    return config, built
