#!/usr/bin/env python3
import argparse
import concurrent.futures
import itertools
import logging
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from proxyUtil._common import (
    add_source_args,
    add_version_arg,
    collect_proxies,
    find_free_ports,
)
from proxyUtil.dnsUtil import isIPv4, isIPv6
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.net import PROXIES, getIP, getIPnCountry, is_alive
from proxyUtil.os_glue import is_tool, killProcess
from proxyUtil.parsers import parse_ss_withPlugin
from proxyUtil.schemes import ss_scheme
from proxyUtil.shadowsocks import ssURI2sslocal
from proxyUtil.utils import format_geo, split2Npart

FREE_SS_URL = "https://raw.githubusercontent.com/freefq/free/master/v2"


def _checker(shadowList, localPort, testDomain, timeOut, tempdir):
    liveProxy = []
    proxy = {k: v.format(LOCAL_PORT=localPort) for k, v in PROXIES.items()}
    pidPath = f"{tempdir}/ss.pid.{localPort}"

    for ss_url in shadowList:
        server, *_ = parse_ss_withPlugin(ss_url)

        if not isIPv4(server) and not isIPv6(server) and not getIP(server):
            continue

        cmd = ssURI2sslocal(ss_url, localPort, pidPath)
        subprocess.run(shlex.split(cmd), check=False)
        time.sleep(0.2)

        if ping := is_alive(testDomain, proxy, timeOut):
            liveProxy.append((ss_url, ping))
            ip, country, country_code = getIPnCountry(proxy, timeOut)
            if ip is None:
                logging.warning(f"[failed] ip={server} with ping={ping}")
            else:
                logging.info(f"[live] {format_geo(ip, country, country_code)} ping={ping}")
        else:
            logging.debug(f"[dead] ip={server}")

        try:
            pid = int(Path(pidPath).read_text().strip())
            os.kill(pid, signal.SIGKILL)
        except (FileNotFoundError, ValueError, ProcessLookupError):
            pass
        time.sleep(0.3)

    return liveProxy


def main(argv=None):
    parser = argparse.ArgumentParser(description="Simple shadowsocks proxy checker")
    add_version_arg(parser)
    parser.add_argument(
        "-d", "--domain", help="test connect domain", default="https://www.google.com"
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
    add_source_args(parser)
    parser.add_argument("-o", "--output", help="output file", default="sortedShadow.txt")
    args = parser.parse_args(argv)

    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logging.basicConfig(level=logging.ERROR, handlers=[ch])

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not is_tool("ss-local"):
        logging.error("ss-local not found, please install shadowsocks client first")
        logging.error("\thttps://github.com/shadowsocks/shadowsocks-libev")
        return 1

    killProcess("ss-local")

    tempdir = tempfile.mkdtemp()
    try:
        lines = collect_proxies(args, free_url=FREE_SS_URL, patterns=[ss_scheme])
        logging.info(f"We have {len(lines)} proxy to check")

        if not lines:
            logging.error("No proxy to check")
            return 1

        N = min(args.threads, len(lines))
        openPort = find_free_ports(args.lport, N)

        with concurrent.futures.ThreadPoolExecutor(max_workers=N) as executor:
            results = executor.map(
                _checker,
                split2Npart(lines, N),
                openPort,
                itertools.repeat(args.domain, N),
                itertools.repeat(args.timeout, N),
                itertools.repeat(tempdir, N),
            )

        liveProxy = list(itertools.chain.from_iterable(results))
        liveProxy.sort(key=lambda x: x[1])
        Path(args.output).write_text("".join(f"{url}\n" for url, _ in liveProxy))
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)


if __name__ == "__main__":
    main()
