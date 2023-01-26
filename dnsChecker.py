#!/usr/bin/env python3
# https://github.com/rthalley/dnspython
# https://dnspython.readthedocs.io
import argparse
import ipaddress
import os
import re
import socket
import urllib
import dns.message  # pip install dnspython[doh,dnssec,idna]
import dns.name
import dns.query
import requests
from bs4 import BeautifulSoup  # pip install beautifulsoup4
from rich.console import Console  # pip install rich
from rich.table import Table
from modules.dnsUtil import *
from modules.logFormatter import *

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[ch])

DEFAULT_TIMEOUT = 3.0
Do53_DEFAULT_ENDPOINT = "8.8.8.8"
DoT_DEFAULT_ENDPOINT = "tls://dns.google:853"
DoH_DEFAULT_ENDPOINT = "https://dns.google/dns-query"

FILTER_CIDRs = ["0.0.0.0/32", "10.10.34.0/24"]

RR = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "SPF", "SRV", "TXT", "CAA", "DNSKEY", "DS"]

console = Console()

def clearScreen():
    #console.print("\033c", end="")
    os.system('cls' if os.name == 'nt' else 'clear')


def isIPv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(ip)
        except socket.error:
            return False
        return ip.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True


def isIPv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
    except socket.error:  # not a valid address
        return False
    return True


def isFilter(ip, CIDR_LIST=FILTER_CIDRs):
    for cidr in CIDR_LIST:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
            return True
    return False


def findURLs(text):
    regex = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(regex, text)
    return urls if urls else []


def scrapeDoH():
    URL = "https://github.com/curl/curl/wiki/DNS-over-HTTPS"
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, 'html.parser')
    results = soup.find_all('tbody')[0].find_all('tr')
    doh = {}
    for row in results[1:]:
        data = row.find_all('td')
        name = data[0].text.strip()
        #urls = findURLs( data[1].text )
        urls = [aTag.get('href') for aTag in data[1].find_all('a')]
        if urls :
            doh[name] = urls
    return doh


def Do53_reolver(domain, rr="A", endpoint=Do53_DEFAULT_ENDPOINT, request_dnssec=False, timeout=DEFAULT_TIMEOUT):
    qname = dns.name.from_text(domain)
    rdtype = dns.rdatatype.from_text(rr)
    req = dns.message.make_query(qname, rdtype, want_dnssec=request_dnssec)
    try:
        res, tcp = dns.query.udp_with_fallback(req, endpoint, timeout=timeout)
        ips = [ item.address for answer in res.answer for item in answer]
        if any(isFilter(ip) for ip in ips):
            logging.critical(f"[Do53] {domain} resolved to {ips} using {endpoint} is Filtered")
        else:
            logging.info(f"[Do53] {domain} resolved to {ips} in {res.time} seconds using {endpoint}")
        return res.time, ips
    except Exception as e:
        logging.error(f"[Do53] Failed to resolve {domain} using {endpoint}: {e}")
        return timeout, []


def DoT_resolver(domain, rr="A", endpoint=DoT_DEFAULT_ENDPOINT, request_dnssec=False, timeout=DEFAULT_TIMEOUT):
    qname = dns.name.from_text(domain)
    rdtype = dns.rdatatype.from_text(rr)
    req = dns.message.make_query(qname, rdtype, want_dnssec=request_dnssec)
    finalEndpoint = endpoint
    if not isIPv4(endpoint) and not isIPv6(endpoint):
        hostname = urllib.parse.urlparse(endpoint).hostname
        ips = Do53_reolver(hostname, "A")
        finalEndpoint = ips[1][0]
    try:
        res = dns.query.tls(req, finalEndpoint, timeout=timeout)
        ips = [ item.address for answer in res.answer for item in answer]
        if any(isFilter(ip) for ip in ips):
            logging.critical(f"[DoT] {domain} resolved to {ips} using {endpoint} is Filtered")
        else:
            logging.info(f"[DoT] {domain} resolved to {ips} in {res.time} seconds using {endpoint}")
        return float(res.time), ips
    except Exception as e:
        logging.error(f"[DoT] Failed to resolve {domain} using {endpoint}: {e}")
        return timeout, []
    

def DoH_resolver(domain, rr="A", endpoint=DoH_DEFAULT_ENDPOINT, request_dnssec=False, timeout=DEFAULT_TIMEOUT):
    qname = dns.name.from_text(domain)
    rdtype = dns.rdatatype.from_text(rr)
    req = dns.message.make_query(qname, rdtype, want_dnssec=request_dnssec)
    try:
        res = dns.query.https(req, endpoint, timeout=timeout)
        ips = [ item.address for answer in res.answer for item in answer]
        if any(isFilter(ip) for ip in ips):
            logging.critical(f"[DoH] {domain} resolved to {ips} using {endpoint} is Filtered")
        else:
            logging.info(f"[DoH] {domain} resolved to {ips} in {res.time} seconds using {endpoint}")
        return res.time.total_seconds(), ips
    except Exception as e:
        logging.error(f"[DoH] Failed to resolve {domain} using {endpoint}: {e}")
        return timeout, []


def main():
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
    args = parser.parse_args()

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
                results.append((name, server, dnsTime, ips))

    if args.dot:
        for name, servers in DoT_URLS.items():
            for server in servers:
                dnsTime, ips = DoT_resolver(args.domain, args.rr, server, args.request_dnssec)
                results.append((name, server, dnsTime, ips))
    
    if args.doh:
        for name, servers in DoH_URLS.items():
            for server in servers:
                dnsTime, ips = DoH_resolver(args.domain, args.rr, server, args.request_dnssec)
                results.append((name, server, dnsTime, ips))
    
    results.sort(key=lambda x: x[2])
    for result in results:
        table.add_row(result[0], result[1], f"{result[2]:.2f} s", ", ".join(result[3]))
    
    #time.sleep(0.1)
    #clearScreen()
    console.print(table)
    

if __name__ == "__main__":
    main()
