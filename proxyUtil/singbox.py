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
import os
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
from .utils import base64Decode, generate_uuid, is_truthy, is_valid_uuid, isBase64, split_csv

__all__ = [
    "MIN_SINGBOX_VERSION_ANYTLS",
    "SCHEMES",
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
        "log": {"level": "warn"},
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
    net = parsed.get("net") or parsed.get("type") or ""
    if net in ("", "tcp", "raw", "none"):
        return None
    if net == "ws":
        block = {"type": "ws", "path": parsed.get("path", "/")}
        if parsed.get("host"):
            block["headers"] = {"Host": parsed["host"]}
        if parsed.get("ed"):
            block["max_early_data"] = int(parsed["ed"])
            block["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return block
    if net == "grpc":
        return {"type": "grpc", "service_name": parsed.get("serviceName") or parsed.get("path", "")}
    if net in ("h2", "http"):
        block = {"type": "http", "path": parsed.get("path", "/")}
        if parsed.get("host"):
            block["host"] = split_csv(parsed["host"])
        return block
    if net == "httpupgrade":
        block = {"type": "httpupgrade", "path": parsed.get("path", "/")}
        if parsed.get("host"):
            block["host"] = parsed["host"]
        return block
    if net == "quic":
        return {"type": "quic"}
    if net in ("xhttp", "splithttp"):
        logging.warning(
            f"sing-box has no {net!r} transport; downgrading to httpupgrade for {parsed.get('add') or parsed.get('address')}"
        )
        block = {"type": "httpupgrade", "path": parsed.get("path", "/")}
        if parsed.get("host"):
            block["host"] = parsed["host"]
        return block
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


def build_singbox_config(url, localPort):
    loaded = urlsplit(url)
    scheme = loaded.scheme
    if scheme not in SCHEMES:
        return None

    try:
        if scheme in ("hysteria2", "hy2"):
            outbound = _outbound_hysteria2(parseHysteria2(loaded))
        elif scheme == "hysteria":
            outbound = _outbound_hysteria(parseHysteria(loaded))
        elif scheme == "tuic":
            outbound = _outbound_tuic(parseTuic(loaded))
        elif scheme == "juicity":
            tuic = _outbound_tuic(parseJuicity(loaded))
            tuic["congestion_control"] = "bbr"
            tuic["udp_relay_mode"] = "native"
            outbound = tuic
        elif scheme == "anytls":
            outbound = _outbound_anytls(parseAnytls(loaded))
        elif scheme == "shadowtls":
            outbound = _outbound_shadowtls(parseShadowTls(loaded))
        elif scheme in ("naive", "naive+https"):
            outbound = _outbound_naive(parseNaive(loaded))
        elif scheme == "ssh":
            outbound = _outbound_ssh(parseSsh(loaded))
        elif scheme == "wireguard":
            outbound = _outbound_wireguard(parseWireguard(loaded))
        elif scheme == "ss":
            outbound = _outbound_shadowsocks(url)
        elif scheme == "trojan":
            outbound = _outbound_trojan(loaded)
        elif scheme == "vless":
            outbound = _outbound_vless(loaded)
        elif scheme == "vmess":
            payload = url[len("vmess://") :]
            if not isBase64(payload):
                return None
            outbound = _outbound_vmess(json.loads(base64Decode(payload)))
        else:
            return None
    except (KeyError, ValueError, TypeError) as err:
        logging.error(f"{url} : {err}")
        return None

    config = json.loads(_SINGBOX_BASE_TPL)
    config["inbounds"][0]["listen_port"] = localPort
    config["outbounds"].append(outbound)
    return config


def writeConfig(url, localPort, path):
    config = build_singbox_config(url, localPort)
    if config is None:
        return None
    name = os.path.join(path, f"singbox_{localPort}.json")
    with open(name, "w") as f:
        json.dump(config, f)
    return name
