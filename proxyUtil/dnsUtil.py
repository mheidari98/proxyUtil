import dns.message  # pip install dnspython[doh,dnssec,idna]
import dns.name
import dns.query
import ipaddress
import re
import requests
from bs4 import BeautifulSoup  # pip install beautifulsoup4
import socket
import logging
import urllib


DEFAULT_TIMEOUT = 3.0
Do53_DEFAULT_ENDPOINT = "8.8.8.8"
DoT_DEFAULT_ENDPOINT = "tls://dns.google:853"
DoH_DEFAULT_ENDPOINT = "https://dns.google/dns-query"

FILTER_CIDRs = ["0.0.0.0/32", "10.10.34.0/24"]

RR = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "SPF", "SRV", "TXT", "CAA", "DNSKEY", "DS"]


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
        logging.error(f"[Do53] Failed to resolve {domain} using {endpoint} : {e}")
        return timeout, []


def DoT_resolver(domain, rr="A", endpoint=DoT_DEFAULT_ENDPOINT, request_dnssec=False, timeout=DEFAULT_TIMEOUT):
    qname = dns.name.from_text(domain)
    rdtype = dns.rdatatype.from_text(rr)
    req = dns.message.make_query(qname, rdtype, want_dnssec=request_dnssec)
    finalEndpoint = endpoint
    if not isIPv4(endpoint) and not isIPv6(endpoint):
        hostname = urllib.parse.urlparse(endpoint).hostname
        dnsTime, ips = Do53_reolver(hostname, "A")
        if not ips :
            logging.error(f"[DoT] Failed to resolve {endpoint} using Do53")
            return timeout, []
        if any(isFilter(ip) for ip in ips):
            logging.error(f"[DoT] {endpoint} resolved to {ips} is Filtered")
            return timeout, []
        finalEndpoint = ips[0]
    try:
        res = dns.query.tls(req, finalEndpoint, timeout=timeout)
        ips = [ item.address for answer in res.answer for item in answer]
        if any(isFilter(ip) for ip in ips):
            logging.critical(f"[DoT] {domain} resolved to {ips} using {endpoint} is Filtered")
        else:
            logging.info(f"[DoT] {domain} resolved to {ips} in {res.time} seconds using {endpoint}")
        return float(res.time), ips
    except Exception as e:
        logging.error(f"[DoT] Failed to resolve {domain} using {endpoint} : {e}")
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
        return float(res.time), ips
    except Exception as e:
        logging.error(f"[DoH] Failed to resolve {domain} using {endpoint} : {e}")
        return timeout, []

