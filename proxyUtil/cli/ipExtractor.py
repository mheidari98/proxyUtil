#!/usr/bin/env python3
"""Extract IPs from shadowsocks, vmess, vless, trojan links."""
import argparse
import ipaddress
import logging
import sys
from pathlib import Path

from proxyUtil._common import add_version_arg
from proxyUtil.dnsUtil import isIPv4, isIPv6
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.net import ScrapURL
from proxyUtil.parsers import extractIPs, parseContent

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.ERROR, handlers=[ch])


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract IPs from shadowsocks, vmess, vless, trojan links"
    )
    add_version_arg(parser)
    parser.add_argument("-f", "--file", help="file contain proxy")
    parser.add_argument("--stdin", help="get proxies from stdin", action="store_true")
    parser.add_argument("--url", help="get proxies from url")
    parser.add_argument("--sort", help="sort output", action="store_true")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-o", "--output", help="output file")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if args.stdin:
        proxies = parseContent(sys.stdin.read().strip())
    elif args.file and (fp := Path(args.file)).is_file():
        proxies = parseContent(fp.read_text(encoding="UTF-8").strip())
    elif args.url:
        proxies = ScrapURL(args.url)
    else:
        logging.error("No proxy to check")
        return

    logging.info(f"Total proxies: {len(proxies)}")

    ips = [ip for ip in (extractIPs(p) for p in proxies) if ip]

    if args.sort:
        ips = [ip for ip in ips if isIPv4(ip) or isIPv6(ip)]
        ips.sort(key=lambda ip: (ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip))))

    output = "\n".join(ips)
    if args.output:
        Path(args.output).write_text(output, encoding="UTF-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
