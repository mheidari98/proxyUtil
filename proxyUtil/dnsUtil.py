from __future__ import annotations

import ipaddress
import logging
import re
import urllib.parse

import dns.message  # pip install dnspython[doh,dnssec,idna]
import dns.name
import dns.query
import dns.rdatatype
import requests
from bs4 import BeautifulSoup  # pip install beautifulsoup4

__all__ = [
    "DEFAULT_TIMEOUT",
    "RR",
    "Do53_DEFAULT_ENDPOINT",
    "Do53_reolver",
    "Do53_resolver",
    "DoH_DEFAULT_ENDPOINT",
    "DoH_resolver",
    "DoT_DEFAULT_ENDPOINT",
    "DoT_resolver",
    "FILTER_CIDRs",
    "findURLs",
    "isFilter",
    "isIPv4",
    "isIPv6",
    "scrapeDoH",
]

DEFAULT_TIMEOUT = 3.0
Do53_DEFAULT_ENDPOINT = "8.8.8.8"
DoT_DEFAULT_ENDPOINT = "tls://dns.google:853"
DoH_DEFAULT_ENDPOINT = "https://dns.google/dns-query"

FILTER_CIDRs = ["0.0.0.0/32", "10.10.34.0/24"]

RR = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "SPF", "SRV", "TXT", "CAA", "DNSKEY", "DS"]

_URL_RE = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")


def isFilter(ip, CIDR_LIST=FILTER_CIDRs):
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(cidr) for cidr in CIDR_LIST)


def findURLs(text):
    return _URL_RE.findall(text)


def scrapeDoH():
    URL = "https://github.com/curl/curl/wiki/DNS-over-HTTPS"
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, "html.parser")
    rows = soup.find_all("tbody")[0].find_all("tr")
    doh = {}
    for row in rows[1:]:
        data = row.find_all("td")
        name = data[0].text.strip()
        if urls := [a.get("href") for a in data[1].find_all("a")]:
            doh[name] = urls
    return doh


def isIPv4(ip):
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def isIPv6(ip):
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def _log_resolution(proto, domain, ips, endpoint, elapsed):
    if any(isFilter(ip) for ip in ips):
        logging.critical(f"[{proto}] {domain} resolved to {ips} using {endpoint} is Filtered")
    else:
        logging.info(f"[{proto}] {domain} resolved to {ips} in {elapsed} seconds using {endpoint}")


def _resolve(proto, domain, rr, endpoint, request_dnssec, timeout, query_fn):
    qname = dns.name.from_text(domain)
    rdtype = dns.rdatatype.from_text(rr)
    req = dns.message.make_query(qname, rdtype, want_dnssec=request_dnssec)
    try:
        res = query_fn(req)
        ips = [item.address for answer in res.answer for item in answer]
        _log_resolution(proto, domain, ips, endpoint, res.time)
        return float(res.time), ips
    except Exception as e:
        logging.error(f"[{proto}] Failed to resolve {domain} using {endpoint} : {e}")
        return timeout, []


def Do53_resolver(
    domain, rr="A", endpoint=Do53_DEFAULT_ENDPOINT, request_dnssec=False, timeout=DEFAULT_TIMEOUT
):
    def query(req):
        res, _tcp = dns.query.udp_with_fallback(req, endpoint, timeout=timeout)
        return res

    return _resolve("Do53", domain, rr, endpoint, request_dnssec, timeout, query)


# typo-preserving alias for backward compatibility
Do53_reolver = Do53_resolver


def DoT_resolver(
    domain, rr="A", endpoint=DoT_DEFAULT_ENDPOINT, request_dnssec=False, timeout=DEFAULT_TIMEOUT
):
    finalEndpoint = endpoint
    if not isIPv4(endpoint) and not isIPv6(endpoint):
        hostname = urllib.parse.urlparse(endpoint).hostname
        _, ips = Do53_resolver(hostname, "A")
        if not ips:
            logging.error(f"[DoT] Failed to resolve {endpoint} using Do53")
            return timeout, []
        if any(isFilter(ip) for ip in ips):
            logging.error(f"[DoT] {endpoint} resolved to {ips} is Filtered")
            return timeout, []
        finalEndpoint = ips[0]

    return _resolve(
        "DoT", domain, rr, endpoint, request_dnssec, timeout,
        lambda req: dns.query.tls(req, finalEndpoint, timeout=timeout),
    )


def DoH_resolver(
    domain, rr="A", endpoint=DoH_DEFAULT_ENDPOINT, request_dnssec=False, timeout=DEFAULT_TIMEOUT
):
    return _resolve(
        "DoH", domain, rr, endpoint, request_dnssec, timeout,
        lambda req: dns.query.https(req, endpoint, timeout=timeout),
    )
