#!/usr/bin/env python3
"""Generate vmess/vless/trojan URLs with CDN IPs as the address."""
import argparse
import ipaddress
import json
import logging
import random
import re
import sys
import urllib.parse
from pathlib import Path
from urllib.parse import urlencode

import requests

from proxyUtil._common import add_version_arg
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.uri import Create_vmess_url
from proxyUtil.utils import base64Decode, isBase64

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.INFO, handlers=[ch])

cdn_url = {
    "arvan": "https://www.arvancloud.ir/fa/ips.txt",
    "cloudflare": "https://www.cloudflare.com/ips-v4",
    "CFplus": "https://raw.githubusercontent.com/mheidari98/CDNs-ip/main/Cloudflare_Organization.txt",
}

_RE_USER_HOSTPORT = re.compile(r"^(.+)@(.+):(\d+)$")
_PASSTHROUGH_KEYS = {"scheme", "pass", "add", "port"}


def parseVlessTrojan(parsed):
    queryDict = {q.split("=", 1)[0]: q.split("=", 1)[1] for q in parsed.query.split("&")}
    queryDict["scheme"] = parsed.scheme
    if m := _RE_USER_HOSTPORT.search(parsed.netloc):
        queryDict["pass"], queryDict["add"], queryDict["port"] = m.groups()
    return queryDict


def unparseVlessTrojan(q):
    head = f"{q['scheme']}://{q['pass']}@{q['add']}:{q['port']}"
    tail = urlencode({k: v for k, v in q.items() if k not in _PASSTHROUGH_KEYS})
    return f"{head}?{tail}"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate vmess/vless/trojan URLs with CDN IPs as the address"
    )
    add_version_arg(parser)
    parser.add_argument("link", help="vmess link")
    parser.add_argument("--cdn", choices=cdn_url.keys(), help="cdn name")
    parser.add_argument("-f", "--file", help="file contains cdn IPs")
    parser.add_argument("--url", help="url to get cdn IPs")
    parser.add_argument("-n", "--number", type=int, help="number of IP to generate (default: all)")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-o", "--output", help="output file")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.cdn or args.url:
        cdnURL = args.url or cdn_url[args.cdn]
        req = requests.get(cdnURL)
        if req.status_code != 200:
            sys.exit(f"Error to get {cdnURL} : {req.status_code}")
        cidrs = req.text.split()
    elif args.file:
        cidrs = Path(args.file).read_text().split()
    else:
        sys.exit("Provide --cdn, --url, or -f")

    ip_list = [str(ip) for cidr in cidrs for ip in ipaddress.IPv4Network(cidr).hosts()]
    if not ip_list:
        sys.exit("Error to get CDN IPs")
    logging.debug(f"{args.cdn} Total IP: {len(ip_list)}")

    if args.number:
        if args.number > len(ip_list):
            sys.exit(
                f"Number of IP to generate ({args.number}) "
                f"is greater than total IP ({len(ip_list)})"
            )
        ip_list = random.sample(ip_list, args.number)

    parsed = urllib.parse.urlparse(args.link)
    if parsed.scheme == "vmess" and isBase64(args.link[8:]):
        jsonLoad = json.loads(base64Decode(args.link[8:]))
        tls = "tls"
    elif parsed.scheme in {"vless", "trojan"}:
        jsonLoad = parseVlessTrojan(parsed)
        tls = "security"
    else:
        sys.exit("Error to parse proxy link")

    if not jsonLoad.get("host"):
        jsonLoad["host"] = jsonLoad["add"]
    if jsonLoad.get(tls) == "tls":
        if jsonLoad.get("sni"):
            jsonLoad["host"] = jsonLoad["sni"]
        else:
            jsonLoad["sni"] = jsonLoad["host"]
        logging.debug(f"sni : {jsonLoad['sni']}")
    logging.debug(f"host: {jsonLoad['host']}")

    builder = Create_vmess_url if parsed.scheme == "vmess" else unparseVlessTrojan
    results = []
    for ip in ip_list:
        jsonLoad["add"] = ip
        results.append(builder(jsonLoad))

    output = "\n".join(results)
    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
