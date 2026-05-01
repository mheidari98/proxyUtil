#!/usr/bin/env python3
# Install xray:    https://github.com/XTLS/Xray-core#installation
# Install v2ray:   https://www.v2fly.org/en_US/guide/install.html
# Install sing-box: https://sing-box.sagernet.org/installation/
import argparse
import logging
import random
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from proxyUtil import cores
from proxyUtil._common import (
    add_source_args,
    add_version_arg,
    collect_proxies,
    find_free_ports,
)
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.net import PROXIES, getIPnCountry, is_alive
from proxyUtil.os_glue import killCore, runCore
from proxyUtil.utils import format_geo, split2Npart

FREE_PROXY_URL = "https://raw.githubusercontent.com/mheidari98/.proxy/main/all"

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.ERROR, handlers=[ch])


@dataclass
class CheckerCfg:
    core: cores.CoreSpec
    binary: str
    tempdir: str
    time2exec: float
    time2kill: float
    ignore_warning: bool
    cancel: threading.Event


def Checker(proxyList, localPort, testDomain, timeOut, cfg: CheckerCfg):
    liveProxy = []
    proxy = {k: v.format(LOCAL_PORT=localPort) for k, v in PROXIES.items()}

    for url in proxyList:
        if cfg.cancel.is_set():
            break

        scheme = urlsplit(url).scheme
        if scheme not in cfg.core.schemes:
            logging.debug(f"{cfg.core.name} doesn't speak {scheme}://; skipping {url}")
            continue

        configName = cfg.core.write_config(url, localPort, cfg.tempdir)
        if configName is None:
            continue

        proc = runCore(cfg.binary, configName)
        try:
            time.sleep(cfg.time2exec)

            ping = is_alive(testDomain, proxy, timeOut)
            if not ping:
                logging.debug("[dead] Not alive")
                continue

            if not cfg.ignore_warning:
                logging.warning(f"[live] with ping={ping}")
                liveProxy.append((url, ping))
                continue

            ip, country, country_code = getIPnCountry(proxy, timeOut)
            if ip is None:
                logging.warning(f"[live] with ping={ping}")
            else:
                logging.info(f"[live] {format_geo(ip, country, country_code)} ping={ping}")
                liveProxy.append((url, ping))
        finally:
            killCore(proc)
            time.sleep(cfg.time2kill)

    return liveProxy


def main(argv=None):
    parser = argparse.ArgumentParser(description="Simple proxy checker")
    add_version_arg(parser)
    parser.add_argument(
        "-d", "--domain", help="test connect domain", default="http://www.gstatic.com/generate_204"
    )
    parser.add_argument(
        "-t", "--timeout", help="timeout in seconds, default is 3", default=3, type=int
    )
    parser.add_argument(
        "-l", "--lport", help="start local port, default is 1080", default=1080, type=int
    )
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-vv", "--debug", help="debug log", action="store_true")
    parser.add_argument(
        "-T", "--threads", help="threads number, default is 10", default=10, type=int
    )
    parser.add_argument("-n", "--number", help="number of proxy to check", type=int)
    parser.add_argument("-s", "--shuffle", help="shuffle proxies", action="store_true")
    parser.add_argument(
        "-c",
        "--core",
        help=(
            "core to validate proxies. Use 'sing-box' for hysteria2/tuic/hy/anytls; "
            "'xray'/'v2ray' speak vmess/vless/trojan/ss/ssr only."
        ),
        choices=cores.CORE_NAMES,
        default="xray",
    )
    parser.add_argument(
        "--t2exec", help="time to execute core, default is 1", default=1, type=float
    )
    parser.add_argument(
        "--t2kill", help="time to kill core, default is 0.1", default=0.1, type=float
    )
    add_source_args(parser)
    parser.add_argument(
        "-i", "--ignore", help="ignore proxy with warning", action="store_false", default=True
    )
    parser.add_argument("-o", "--output", help="output file", default="sortedProxy.txt")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    spec = cores.get(args.core)
    binary = cores.resolve(spec)
    if not binary:
        return 1
    logging.info(f"using {spec.name} at {binary}")
    logging.info(f"{spec.name} validates: {sorted(spec.schemes)}")

    lines = collect_proxies(args, free_url=FREE_PROXY_URL)

    if args.shuffle:
        random.shuffle(lines)
    if args.number:
        lines = lines[: args.number]
    logging.info(f"We have {len(lines)} proxy to check")

    if not lines:
        logging.error("No proxy to check")
        return None

    N = min(args.threads, len(lines))
    openPort = find_free_ports(args.lport, N)
    logging.debug(f"open port: {openPort}")

    cancel = threading.Event()

    with tempfile.TemporaryDirectory() as tempdir:
        cfg = CheckerCfg(
            core=spec,
            binary=binary,
            tempdir=tempdir,
            time2exec=args.t2exec,
            time2kill=args.t2kill,
            ignore_warning=args.ignore,
            cancel=cancel,
        )

        liveProxy: list[tuple[str, int]] = []
        with ThreadPoolExecutor(max_workers=N) as executor:
            futures = [
                executor.submit(Checker, proxyList, localPort, args.domain, args.timeout, cfg)
                for proxyList, localPort in zip(split2Npart(lines, N), openPort, strict=False)
            ]
            try:
                for future in as_completed(futures):
                    liveProxy.extend(future.result())
            except KeyboardInterrupt:
                cancel.set()
                logging.info("CTRL+C pressed")

    liveProxy.sort(key=lambda x: x[1])
    body = "".join(f"{url}\n" for url, _ping in liveProxy)
    Path(args.output).write_text(body, encoding="utf-8")
    return None


if __name__ == "__main__":
    main()
