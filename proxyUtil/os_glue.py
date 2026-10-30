"""OS / process / proxy-system glue."""

from __future__ import annotations

import logging
import os
import platform
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import psutil

__all__ = [
    "PROXYCHAINS",
    "augment_local_path",
    "chmodX",
    "clearScreen",
    "get_OS",
    "get_arch",
    "installDocker",
    "is_port_in_use",
    "is_tool",
    "killCore",
    "killProcess",
    "runCore",
    "set_proxychains",
    "set_system_proxy",
    "unixKillCore",
    "unixRunCore",
    "winKillCore",
    "winRunCore",
]

PROXYCHAINS = """
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
quiet_mode

[ProxyList]
socks5  127.0.0.1 {LOCAL_PORT}
"""


def is_tool(name):
    return shutil.which(name) is not None


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0


def killProcess(processName, cmdline=None):
    for p in psutil.process_iter(attrs=["pid", "name"]):
        if processName in p.name() and (cmdline is None or cmdline in p.cmdline()):
            for child in p.children():
                os.kill(child.pid, signal.SIGKILL)
            os.kill(p.pid, signal.SIGKILL)


def get_OS():
    name = platform.system()
    logging.debug(f"OS: {name}")
    match name:
        case "Linux":
            return "linux"
        case "Darwin":
            return "macos"
        case "Windows":
            return "windows"
    logging.error("Unsupported OS")
    sys.exit(1)


def get_arch():
    arch = platform.machine()
    logging.debug(f"Architecture: {arch}")
    match arch:
        case "x86_64" | "AMD64":
            return "64"
        case "i386" | "i686":
            return "32"
        case "aarch64":
            return "arm64-v8a"
        case "armv7l":
            return "arm32-v7a"
    logging.error("Unsupported Architecture")
    sys.exit(1)


def chmodX(path):
    if get_OS() == "windows":
        return
    p = Path(path)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def clearScreen():
    os.system("cls" if os.name == "nt" else "clear")


def winRunCore(core, configName):
    return subprocess.Popen(shlex.split(f"{core} run -c {configName}"), stdout=subprocess.PIPE)


def unixRunCore(core, configName):
    return subprocess.Popen(
        shlex.split(f"{core} run -c {configName}"),
        stdout=subprocess.PIPE,
        preexec_fn=os.setsid,
    )


def winKillCore(proc):
    proc.kill()


def unixKillCore(proc):
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)


def runCore(core, configName):
    """Spawn `core` validating `configName`. Picks Win/Unix runner."""
    return winRunCore(core, configName) if get_OS() == "windows" else unixRunCore(core, configName)


def killCore(proc):
    """Kill a process started by `runCore`."""
    return winKillCore(proc) if get_OS() == "windows" else unixKillCore(proc)


def augment_local_path():
    """Add ./xray, ./v2ray, ./sing-box dirs to PATH (idempotent)."""
    parts = os.environ.get("PATH", "").split(os.pathsep)
    additions = [f".{os.sep}{sub}" for sub in ("xray", "v2ray", "sing-box")]
    new_parts = [p for p in additions if p not in parts]
    if new_parts:
        os.environ["PATH"] = os.pathsep.join([*parts, *new_parts])


def set_proxychains(localPort=1080):
    pchPath = Path("~/.proxychains/proxychains.conf").expanduser()
    pchPath.parent.mkdir(parents=True, exist_ok=True)
    if pchPath.exists():
        shutil.copy(pchPath, pchPath.with_suffix(pchPath.suffix + ".bak"))
    pchPath.write_text(PROXYCHAINS.format(LOCAL_PORT=localPort))
    logging.info("proxychains.conf updated!")


def set_system_proxy(proxyHost="127.0.0.1", proxyPort=1080, proxyType="socks5", enable=True):
    if os.name == "nt":
        logging.info("Not Implemented for Windows")
        return

    SHELL = os.environ.get("SHELL") or ""
    if "zsh" in SHELL:
        rc = Path("~/.zshrc").expanduser()
    elif "bash" in SHELL:
        rc = Path("~/.bashrc").expanduser()
    else:
        logging.error(f"Not supported SHELL: {SHELL}")
        return

    proxy = f"{proxyType}://{proxyHost}:{proxyPort}"
    all_proxy = f"export all_proxy={proxy}"
    no_proxy = "export no_proxy=localhost,127.0.0.0/8,192.168.0.0/16,::1"

    lines = [
        line
        for line in rc.read_text().splitlines(keepends=True)
        if not line.startswith(("export all_proxy=", "export no_proxy="))
    ]
    if enable:
        lines.append(f"{all_proxy} && {no_proxy}\n")
    rc.write_text("".join(lines))
    logging.info("set system proxy done!" if enable else "unset proxy done!")


def installDocker():
    if is_tool("docker"):
        logging.info("Docker Installed")
        return
    try:
        logging.info("Docker Not Found.\nInstalling Docker ...")
        subprocess.run("curl https://get.docker.com | sh", shell=True, check=True)
        if subprocess.call(["systemctl", "is-active", "--quiet", "docker"]):
            subprocess.call(["systemctl", "enable", "--now", "--quiet", "docker"])
        time.sleep(2)
    except subprocess.CalledProcessError as e:
        sys.exit(f"Download Failed: {e}")
    except PermissionError:
        sys.exit("root privileges required")
    logging.info("Docker Installed")
