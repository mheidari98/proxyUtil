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


def _ss_userinfo(method: str, password: str, *, strip_pad: bool = False) -> str:
    encoded = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode()
    return encoded.replace("=", "") if strip_pad else encoded


def Create_ss_url(server, server_port, method, password):
    return f"ss://{_ss_userinfo(method, password)}@{server}:{server_port}"


def Create_ss_url_withPlugin(
    server, server_port, method, password, plugin="", plugin_opts="", tag=""
):
    extended = f"/?plugin={quote_plus(f'{plugin};{plugin_opts}')}" if (plugin or plugin_opts) else ""
    tag = tag or "Woman,Life,Freedom"
    userinfo = _ss_userinfo(method, password, strip_pad=True)
    return f"ss://{userinfo}@{server}:{server_port}{extended}#{tag}"


def Create_vmess_url(jsonLoad):
    payload = json.dumps(jsonLoad, indent=4).encode("utf-8") + b"\n"
    return f"vmess://{base64.b64encode(payload).decode()}"


def processShadowJson(jsonTxt):
    """Convert SIP008 / shadowsocks JSON array to a list of `ss://...` URLs."""
    return [
        Create_ss_url(item["server"], item["server_port"], item["method"], item["password"])
        for item in json.loads(jsonTxt)
    ]
