#!/usr/bin/env python3
# https://github.com/rthalley/dnspython
# https://dnspython.readthedocs.io
import argparse
import logging

from rich.console import Console
from rich.table import Table

from proxyUtil._common import add_version_arg
from proxyUtil.dnsUrl import Do53_URLS, DoH_URLS, DoT_URLS
from proxyUtil.dnsUtil import (
    DEFAULT_TIMEOUT,
    RR,
    Do53_resolver,
    DoH_resolver,
    DoT_resolver,
)
from proxyUtil.logFormatter import CustomFormatter

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(
    level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s", handlers=[ch]
)

console = Console()


def main(argv=None):
    parser = argparse.ArgumentParser(description="DNS Checker")
    add_version_arg(parser)
    parser.add_argument(
        "-d", "--domain", help="Domain to check (default: example.com)", default="example.com"
    )
    parser.add_argument(
        "-r", "--rr", help="Record type to check (default: A)", default="A", choices=RR
    )
    parser.add_argument("-v", "--verbose", help="Verbose output", action="store_true")
    parser.add_argument(
        "-s", "--request-dnssec", help="Request DNSSEC", action="store_true", default=False
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help=f"DNS Timeout (default: {DEFAULT_TIMEOUT})",
        default=DEFAULT_TIMEOUT,
        type=float,
    )
    parser.add_argument("--do53", help="check DNS over UDP", action="store_true")
    parser.add_argument("--doh", help="check DNS over HTTPS", action="store_true")
    parser.add_argument("--dot", help="check DNS over TLS", action="store_true")
    parser.add_argument("--all", help="check all DNS over UDP, DoH and DoT", action="store_true")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if args.all:
        args.do53 = args.doh = args.dot = True

    logging.info(f"Domain: {args.domain}")
    logging.info(f"Record type: {args.rr}")

    table = Table(
        show_lines=True,
        show_header=True,
        header_style="bold magenta",
        row_styles=["dim", ""],
        highlight=True,
    )
    table.add_column("DNS NAME", style="bright_cyan", justify="center")
    table.add_column("DNS IP", style="bright_cyan", justify="center")
    table.add_column("Time", style="bright_yellow", justify="center")
    table.add_column("IPs", style="bright_green", justify="center")

    probes = []
    if args.do53:
        probes.append((Do53_resolver, Do53_URLS))
    if args.dot:
        probes.append((DoT_resolver, DoT_URLS))
    if args.doh:
        probes.append((DoH_resolver, DoH_URLS))

    results = [
        (name, server, dnsTime * 100, ips)
        for resolver, urls in probes
        for name, servers in urls.items()
        for server in servers
        for dnsTime, ips in [resolver(args.domain, args.rr, server, args.request_dnssec)]
    ]

    results.sort(key=lambda x: x[2])
    for name, server, ms, ips in results:
        table.add_row(name, server, f"{ms:.2f} ms", ", ".join(ips))

    console.print(table)


if __name__ == "__main__":
    main()
