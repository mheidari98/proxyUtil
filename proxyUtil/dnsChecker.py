#!/usr/bin/env python3
# https://github.com/rthalley/dnspython
# https://dnspython.readthedocs.io
import argparse
from rich.console import Console  # pip install rich
from rich.table import Table
from proxyUtil import *

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[ch])

console = Console()

def main(argv=sys.argv):
    parser = argparse.ArgumentParser(description="DNS Checker")
    parser.add_argument("-d", "--domain", help="Domain to check (default: example.com)", default="example.com")
    parser.add_argument("-r", "--rr", help="Record type to check (default: A)", default="A", choices=RR)
    parser.add_argument("-v", "--verbose", help="Verbose output", action="store_true")
    parser.add_argument("-s", "--request-dnssec", help="Request DNSSEC", action="store_true", default=False)
    parser.add_argument("-t", "--timeout", help=f"DNS Timeout (default: {DEFAULT_TIMEOUT})", default=DEFAULT_TIMEOUT, type=float)
    parser.add_argument("--do53", help="check DNS over UDP", action="store_true", default=False)
    parser.add_argument("--doh", help="check DNS over HTTPS", action="store_true", default=False)
    parser.add_argument("--dot", help="check DNS over TLS", action="store_true", default=False)
    parser.add_argument("--all", help="check all DNS over UDP, DoH and DoT", action="store_true", default=False)
    args = parser.parse_args(argv[1:])

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if args.all:
        args.do53 = True
        args.doh = True
        args.dot = True

    logging.info(f"Domain: {args.domain}")
    logging.info(f"Record type: {args.rr}")

    table = Table(show_lines=True, show_header=True, header_style="bold magenta", 
                    row_styles=["dim", ""], highlight=True)
    
    table.add_column("DNS NAME", style="bright_cyan", justify="center")
    table.add_column("DNS IP", style="bright_cyan", justify="center")
    table.add_column("Time", style="bright_yellow", justify="center")
    table.add_column("IPs", style="bright_green", justify="center")

    results = []

    if args.do53:
        for name, servers in Do53_URLS.items():
            for server in servers:
                dnsTime, ips = Do53_reolver(args.domain, args.rr, server, args.request_dnssec)
                results.append((name, server, dnsTime*100, ips))

    if args.dot:
        for name, servers in DoT_URLS.items():
            for server in servers:
                dnsTime, ips = DoT_resolver(args.domain, args.rr, server, args.request_dnssec)
                results.append((name, server, dnsTime*100, ips))
    
    if args.doh:
        for name, servers in DoH_URLS.items():
            for server in servers:
                dnsTime, ips = DoH_resolver(args.domain, args.rr, server, args.request_dnssec)
                results.append((name, server, dnsTime*100, ips))
    
    results.sort(key=lambda x: x[2])
    for result in results:
        table.add_row(result[0], result[1], f"{result[2]:.2f} ms", ", ".join(result[3]))
    
    #time.sleep(0.1)
    #clearScreen()
    console.print(table)
    

if __name__ == "__main__":
    main()
