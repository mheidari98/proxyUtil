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
from modules.myUtil import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

cdn_url = { 
    'arvan'         : "https://www.arvancloud.ir/fa/ips.txt" , 
    'cloudflare'    : "https://www.cloudflare.com/ips-v4" ,
    }

def main():
    parser = argparse.ArgumentParser(description="Generating vmess url with CDN IPs as address and our domain as host")
    parser.add_argument("url", help="vmess link")
    parser.add_argument("--cdn", choices=cdn_url.keys(), help="cdn name", required=True)
    parser.add_argument("-n", "--number", type=int, help="number of IP to generate (default: all)")
    parser.add_argument('-v', "--verbose", help="increase output verbosity", action="store_true", default=False)
    parser.add_argument("-o", "--output", help="output file")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    req = requests.get(cdn_url[args.cdn])
    if req.status_code != 200:
        logging.error(f"Error to get {cdn_url[args.cdn]} : {req.status_code}")
        exit(1)

    ip_list = []
    for cidr in req.text.splitlines():
        ip_list.extend([str(ip) for ip in ipaddress.IPv4Network(cidr).hosts()])
    logging.debug(f"{args.cdn} Total IP: {len(ip_list)}")

    if args.number :
        if args.number > len(ip_list) :
            logging.error(f"Number of IP to generate ({args.number}) is greater than total IP ({len(ip_list)})")
            exit(1)
        ip_list = random.sample(ip_list, args.number)

    ParseResult = urllib.parse.urlparse(args.url)  # <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
    if ParseResult.scheme == "vmess" and isBase64(args.url[8:]):
        jsonLoad = json.loads(base64Decode(args.url[8:]))
    else :
        logging.error("Error to parse proxy link")
        exit(1)

    if 'tls' in jsonLoad and jsonLoad['tls']=='tls' :
        if 'sni' in jsonLoad and jsonLoad['sni'] :
            jsonLoad['host'] = jsonLoad['sni']
        elif 'host' in jsonLoad and jsonLoad['host'] :
            jsonLoad['sni'] = jsonLoad['host']
        logging.debug(f"sni : {jsonLoad['sni']}")
    elif ('host' not in jsonLoad) or (not jsonLoad['host']) :
        jsonLoad['host'] = jsonLoad['add']
    
    logging.debug(f"host: {jsonLoad['host']}")

    results = []

    for ip in ip_list:
        jsonLoad['add'] = ip
        results.append( Create_vmess_url(jsonLoad) )

    outputs = '\n'.join(results) 
    if args.output :
        with open(args.output, 'w') as f :
            f.write(outputs)
    else :
        print(outputs)


if __name__ == '__main__':
    main()

