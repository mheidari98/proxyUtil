"""ss-libev cmdline glue: ssURI <-> ss-local CLI string and JSON config."""

from __future__ import annotations

import json

from .parsers import parse_ss_withPlugin
from .utils import finder

__all__ = [
    "ssConfig2json",
    "ssURI2sslocal",
    "sslocal2ssURI",
]


def sslocal2ssURI(cmd):
    import base64

    server = finder(cmd, "-s")
    server_port = finder(cmd, "-p")
    method = finder(cmd, "-m")
    password = finder(cmd, "-k")
    msg = f"{method}:{password}@{server}:{server_port}"
    return f"ss://{base64.b64encode(msg.encode('ascii')).decode('ascii')}"


def ssURI2sslocal(ss_url, localPort=1080, file2storePID=""):
    server, server_port, method, password, plugin, plugin_opts, _tag = parse_ss_withPlugin(ss_url)
    extended = ""
    if plugin or plugin_opts:
        extended = f" --plugin {plugin} --plugin-opts '{plugin_opts}'"
    cmd = (
        f"ss-local -s {server} -p {server_port} -l {localPort} "
        f"-m {method} -k '{password}'{extended}"
    )
    if file2storePID:
        cmd += f" -f {file2storePID}"
    return cmd


def ssConfig2json(ss_url, local_port=1080, configFile="CONFIG.json"):
    # https://manpages.debian.org/testing/shadowsocks-libev/shadowsocks-libev.8.en.html
    server, server_port, method, password, plugin, plugin_opts, _tag = parse_ss_withPlugin(ss_url)
    config = {
        "server": server,
        "server_port": int(server_port),
        "method": method,
        "password": password,
        "local_port": local_port,
        "plugin": plugin,
        "plugin_opts": plugin_opts,
    }
    with open(configFile, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=4)
