#!/usr/bin/env python3
# -*- coding=utf-8 -*-
#   Python wrapper for the Cloudflare Client API v4 :
#           https://github.com/cloudflare/python-cloudflare
#   Global API Key: 
#           https://dash.cloudflare.com/profile/api-tokens
#   Cloudflare API: 
#           https://developers.cloudflare.com/api
#   Cloudflare API v4 Documentation - deprecated: 
#           https://api.cloudflare.com/
#
#   cannot use this API for domains with a .cf, .ga, .gq, .ml, or .tk TLD (top-level domain). 
#   To configure the DNS settings for this domain, use the Cloudflare Dashboard.
#

import argparse
import re
import CloudFlare  # pip install cloudflare
from rich.console import Console  # pip install rich
from rich.table import Table
from proxyUtil import *

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.INFO, handlers=[ch])

console = Console()


def main(argv=sys.argv):
    parser = argparse.ArgumentParser(description="Simple Cloudflare DNS Recorder")
    parser.add_argument("email", help="Cloudflare email")
    parser.add_argument("token", help="Cloudflare token")
    parser.add_argument("domain", help="Domain to record")
    parser.add_argument("subdomain", help="Subdomain to record")
    parser.add_argument("-f", "--file", help="File containing the Ip(s) to record")
    parser.add_argument("--stdin", help="Read the Ip(s) from stdin", action="store_true", default=False)
    parser.add_argument('-v', "--verbose", help="increase output verbosity", action="store_true", default=False)

    args = parser.parse_args(argv[1:])

    if args.verbose:
        table1 = Table(show_lines=True, show_header=True, header_style="bold magenta", 
                    row_styles=["dim", ""], highlight=True)
        table1.add_column("Name", style="cyan", no_wrap=True)
        table1.add_column("Type", style="green")
        table1.add_column("Plan", style="blue")
        table1.add_column("ID", style="magenta")

        table2 = Table(show_lines=True, show_header=True, header_style="bold magenta", 
                    row_styles=["dim", ""], highlight=True)
        table2.add_column("SSL", style="cyan", no_wrap=True)
        table2.add_column("IPv6", style="green")

        table3 = Table(show_lines=True, show_header=True, header_style="bold magenta",
                    row_styles=["dim", ""], highlight=True)
        table3.add_column("Name", style="cyan", no_wrap=True)
        table3.add_column("Type", style="green")
        table3.add_column("Value", style="blue")
        table3.add_column("TTL", style="magenta")
        table3.add_column("ID", style="yellow")

    if args.stdin:
        IPs = sys.stdin.read()
    elif args.file and os.path.isfile(args.file):
        with open(args.file, 'r', encoding='UTF-8') as file:
            IPs = file.read()
    else:
        IPs = input("IP(s): ")
    
    IPs = [ip.strip() for ip in IPs.split() if isIPv4(ip)]

    if not IPs:
        console.print("No valid IP(s) found", style="bold red")
        exit(1)

    cf = CloudFlare.CloudFlare(email=args.email, token=args.token, debug=False)

    params = {"name": f"{args.domain}", "per_page":1}
    try:
        zone = cf.zones.get(params = params)[0]
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit("/zones %d %s - api call failed" % (e, e))
    except Exception as e:
        exit("/zones.get - %s - api call failed" % (e))

    zone_name = zone['name']
    zone_id   = zone['id']
    zone_type = zone['type']
    zone_plan = zone['plan']['name']
    
    settings_ssl = cf.zones.settings.ssl.get(zone_id)
    ssl_status = settings_ssl['value']

    settings_ipv6 = cf.zones.settings.ipv6.get(zone_id)
    ipv6_status = settings_ipv6['value']

    if args.verbose:
        table1.add_row(zone_name, zone_type, zone_plan, zone_id)
        console.print(table1)
        table2.add_row(ssl_status, ipv6_status)
        console.print(table2)

    try:
        dns_records = cf.zones.dns_records.get(zone_id)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        sys.stderr.write('/zones/dns_records %d %s - api call failed\n' % (e, e))
        
    prog = re.compile('\.*'+zone_name+'$')
    dns_records = sorted(dns_records, key=lambda v: prog.sub('', v['name']) + '_' + v['type'])

    for dns_record in dns_records:
        r_name = dns_record['name']
        r_type = dns_record['type']
        r_value = dns_record['content']
        r_ttl = dns_record['ttl']
        if zone_type == 'secondary':
            r_id = 'secondary'
        else:
            r_id = dns_record['id']
        
        if r_name == f"{args.subdomain}.{args.domain}" and r_type == "A":
            if r_value in IPs:
                IPs.remove(r_value)
                if args.verbose:
                    table3.add_row(r_name, r_type, r_value, str(r_ttl), r_id)
                console.print(f"Found {r_name} {r_type} {r_value}", style="bold green")
            else:
                cf.zones.dns_records.delete(zone_id, r_id)
                console.print(f"Deleted {r_name} {r_type} {r_value}", style="bold red")

    for ip in IPs:
        dns_record = {
            'type': 'A',
            'name': f"{args.subdomain}",
            'content': ip,
            'ttl': 1,
            'proxied': False
        }
        try:
            r = cf.zones.dns_records.post(zone_id, data=dns_record)
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            exit('/zones/dns_records.post %d %s - api call failed' % (e, e))
        except Exception as e:
            exit('/zones/dns_records.post - %s - api call failed' % (e))

        r_name = r['name']
        r_type = r['type']
        r_value = r['content']
        r_ttl = r['ttl']
        r_id = r['id']

        if args.verbose:
            table3.add_row(r_name, r_type, r_value, str(r_ttl), r_id)
        console.print(f"Added {r_name} {r_type} {r_value}", style="bold green")

    if args.verbose:
        console.print(table3)


if __name__ == "__main__":
    main()
