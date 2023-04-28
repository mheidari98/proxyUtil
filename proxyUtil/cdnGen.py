#!/usr/bin/env python3
#########################################################################
# Generating vmess url with CDN IPs as address and our domain as host   #
#                                                                       #
# Usage: ./cdnGen.py "vmess://..." --cdn arvan -n 100 -o output.txt     #
#   --cdn: CDN name                                                     #
#   -o: output file                                                     #
#   -n: number of IP to generate                                        #
# Output:                                                               #
#   vmess url with                                                      #
#       address: CDN IP                                                 #
#       host: our domain                                                #
##########################################################################
import argparse
import ipaddress
import random
from proxyUtil import *

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.INFO, handlers=[ch])

cdn_url = { 
    'arvan'         : "https://www.arvancloud.ir/fa/ips.txt" , 
    'cloudflare'    : "https://www.cloudflare.com/ips-v4" ,
    'CFplus'        : "https://raw.githubusercontent.com/mheidari98/CDNs-ip/main/Cloudflare_Organization.txt" ,
    }

def parseVlessTrojan(ParseResult):
    queryDict = { q.split('=', 1)[0] : q.split('=', 1)[1] for q in ParseResult.query.split('&') }
    queryDict['scheme'] = ParseResult.scheme
    if (res := re.search(f"^(.+)@(.+):(\d+)$", ParseResult.netloc)):
        queryDict['pass'], queryDict['add'], queryDict['port'] = res.groups()
    return queryDict


def unparseVlessTrojan(queryDict):
    part1 = f"{queryDict['scheme']}://{queryDict['pass']}@{queryDict['add']}:{queryDict['port']}"
    part2 = urlencode({key:value for key, value in queryDict.items() if key not in ['scheme', 'pass','add', 'port']})
    return f"{part1}?{part2}"


def main(argv=sys.argv):
    parser = argparse.ArgumentParser(description="Generating vmess url with CDN IPs as address and our domain as host")
    parser.add_argument("link", help="vmess link")
    parser.add_argument("--cdn", choices=cdn_url.keys(), help="cdn name")
    parser.add_argument("-f", "--file", help="file contains cdn IPs")
    parser.add_argument("--url", help="url to get cdn IPs")
    parser.add_argument("-n", "--number", type=int, help="number of IP to generate (default: all)")
    parser.add_argument('-v', "--verbose", help="increase output verbosity", action="store_true", default=False)
    parser.add_argument("-o", "--output", help="output file")
    args = parser.parse_args(argv[1:])

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.cdn or args.url :
        cdnURL = args.url if args.url else cdn_url[args.cdn]
        req = requests.get(cdnURL)
        if req.status_code != 200:
            logging.error(f"Error to get {cdnURL} : {req.status_code}")
            exit(1)
        cidrs = req.text.split()

    elif args.file :
        with open(args.file, 'r') as f :
            cidrs = f.read().split()

    ip_list = []
    for cidr in cidrs:
        ip_list.extend([str(ip) for ip in ipaddress.IPv4Network(cidr).hosts()])

    if not ip_list :
        logging.error("Error to get CDN IPs")
        exit(1)
    logging.debug(f"{args.cdn} Total IP: {len(ip_list)}")

    if args.number :
        if args.number > len(ip_list) :
            logging.error(f"Number of IP to generate ({args.number}) is greater than total IP ({len(ip_list)})")
            exit(1)
        ip_list = random.sample(ip_list, args.number)

    ParseResult = urllib.parse.urlparse(args.link)  # <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
    if ParseResult.scheme == "vmess" and isBase64(args.link[8:]):
        jsonLoad = json.loads(base64Decode(args.link[8:]))
        tls = 'tls'
    elif ParseResult.scheme in ["vless", "trojan"] :
        jsonLoad = parseVlessTrojan(ParseResult)
        tls = 'security'
    else :
        logging.error("Error to parse proxy link")
        exit(1)

    if ('host' not in jsonLoad) or (not jsonLoad['host']) :
        jsonLoad['host'] = jsonLoad['add']
    if tls in jsonLoad and jsonLoad[tls]=='tls' :
        if 'sni' in jsonLoad and jsonLoad['sni'] :
            jsonLoad['host'] = jsonLoad['sni']
        else :
            jsonLoad['sni'] = jsonLoad['host']
        logging.debug(f"sni : {jsonLoad['sni']}")
    logging.debug(f"host: {jsonLoad['host']}")

    results = []

    for ip in ip_list:
        jsonLoad['add'] = ip
        if ParseResult.scheme == "vmess" :
            results.append( Create_vmess_url(jsonLoad) )
        elif ParseResult.scheme in ["vless", "trojan"] :
            results.append( unparseVlessTrojan(jsonLoad) )

    outputs = '\n'.join(results) 
    if args.output :
        with open(args.output, 'w') as f :
            f.write(outputs)
    else :
        print(outputs)


if __name__ == '__main__':
    main()

