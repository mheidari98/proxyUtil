"""URL builders for proxy schemes (the inverse of `parsers`)."""

from __future__ import annotations

import base64
import json
from urllib.parse import quote_plus

__all__ = [
    "Create_ss_url",
    "Create_ss_url_withPlugin",
    "Create_vmess_url",
    "processShadowJson",
]


def Create_ss_url(server, server_port, method, password):
    return (
        "ss://"
        + base64.urlsafe_b64encode((method + ":" + password).encode()).decode("utf-8")
        + f"@{server}:{server_port}"
    )


def Create_ss_url_withPlugin(
    server, server_port, method, password, plugin="", plugin_opts="", tag=""
):
    extended = ""
    if plugin or plugin_opts:
        extended = f"/?plugin={quote_plus(f'{plugin};{plugin_opts}')}"
    tag = tag if tag else "Woman,Life,Freedom"
    userinfo = (
        base64.urlsafe_b64encode((method + ":" + password).encode())
        .decode("utf-8")
        .replace("=", "")
    )
    return f"ss://{userinfo}@{server}:{server_port}{extended}#{tag}"


def Create_vmess_url(jsonLoad):
    return (
        "vmess://"
        + base64.b64encode(json.dumps(jsonLoad, indent=4).encode("utf-8") + b"\n").decode()
    )


def processShadowJson(jsonTxt):
    """Convert SIP008 / shadowsocks JSON array to a list of `ss://...` URLs."""
    result = []
    for line in json.loads(jsonTxt):
        ss = Create_ss_url(line["server"], line["server_port"], line["method"], line["password"])
        result.append(ss)
    return result
