#!/usr/bin/env python3
#########################################################################
# Exctraction IP from shadowsocks, vmess, vless, trojan links           #
#                                                                       #
# Usage: ipExtractor "vmess://..." -o output.txt                        #
#  -o: output file                                                      #
# Output:                                                               #
#   IP list                                                             #
##########################################################################
import argparse
import ipaddress
from proxyUtil import *

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.ERROR, handlers=[ch])


def main(argv=sys.argv):
    parser = argparse.ArgumentParser(description="Exctraction IP from shadowsocks, vmess, vless, trojan links")
    parser.add_argument("-f", "--file", help="file contain proxy")
    parser.add_argument('--stdin', help="get proxies from stdin", action='store_true', default=False)
    parser.add_argument('--url', help="get proxies from url")
    parser.add_argument('--sort', help="sort output", action='store_true', default=False)
    parser.add_argument('-v', "--verbose", help="increase output verbosity", action="store_true", default=False)
    parser.add_argument('-o', '--output', help="output file")
    args = parser.parse_args(argv[1:])

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    if args.stdin:
        proxies = parseContent(sys.stdin.read().strip())
    elif args.file and os.path.isfile(args.file):
        with open(args.file, 'r', encoding='UTF-8') as file:
            proxies = parseContent(file.read().strip())
    elif args.url:
        proxies = ScrapURL(args.url)
    else:
        logging.error("No proxy to check")
        return

    logging.info(f"Total proxies: {len(proxies)}")

    ips = list(filter(None, map(extractIPs, proxies)))
    
    if args.sort:
        ips = [ip for ip in ips if isIPv4(ip) or isIPv6(ip)]
        ips = sorted(ips, key=lambda ip: int(ipaddress.IPv4Address(ip)))
    
    outputs = '\n'.join(ips)
    if args.output :
        with open(args.output, 'w', encoding='UTF-8') as f :
            f.write(outputs)
    else :
        print(outputs)


if __name__ == "__main__":
    main()
